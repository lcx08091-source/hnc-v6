// fp_distill.go — 单机快速蒸馏模式(Fast Personal Distill)
//
// 解决痛点:
//  1. fp_learn.go 原本只读热点接口 run/dpi_flows.json, 完全不消费本机真值样本
//     run/label_samples.YYYYMMDD.jsonl, 且单机门槛高达 Support >= 50。
//  2. startup_fp.go 受限于 startupLearnEvery = 30m、startupGapSec = 600s、
//     startupMinStarts = 3.0 以及 dpid 侧 labelSamplesDedupWindow = 600s,
//     导致个人用户在 5~15 分钟集中自测(5~20 条连接、1~3 次冷启动)时 0 产出。
//  3. 直接下调 minSamples 会把 Android System WebView / Chromium / 默认 OkHttp(Conscrypt)
//     或未定制 Cronet 的通用 TLS 指纹在小样本单 App 测试时误判为专属指纹。
//
// 核心安全机制(五层防误判):
//   - 层 1(先验熔断): 浏览器/系统 WebView 包名真值污染标记 + VPN/代理导管包排除 +
//     data/dpi_ja4_fingerprints.json browser 种子与 Chromium/BoringSSL 标准密码套件哈希识别。
//   - 层 2(跨源负样本联合纯度): 同时联合最近 N 天全量 label_samples、现有热点学习表
//     fpStore.m(含 _other 未知站点流量)计算跨应用纯度, 任一非同源应用共现即降级。
//   - 层 3(协议栈四档分层):
//   - exclusive       — 高置信度专属指纹(自定义 ALPN / 定制 QTP / 通过背景对照组门控的独立栈)
//   - vendor_family   — 同厂多应用共享网络栈(如字节 TTNet / 阿里 ANet / 米哈游同系, 不绑单一 App)
//   - provisional     — 样本或背景对照不足的候选栈(提示用户再测 1~2 个其它 App 对照, 绝不盲目放行)
//   - generic_stack   — 系统 WebView / 浏览器 / 通用 OkHttp·Cronet 栈(主动标 Generic, 拦截种子与手工误绑)
//   - 层 4(冷启动前台真值辅助切分): 融合 run/self_fg.YYYYMMDD.jsonl 前台切换时刻与 45s 短静默窗,
//     剔除 tierHidden(广告/统计 SDK/公共 CDN)token, 支持 1~2 次冷启动在严格独占特征下安全生效。
//   - 层 5(幂等游标 + 群智隔离): 独立维护 data/fp_distill_state.json 增量游标, 反复点击「立即蒸馏」
//     绝不重复累加计数; 保持真实 Support 不虚增且置信度封顶 <= 0.78, 天然被 rulepack.go
//     (Support >= 50 && Conf >= 0.80)挡在本机之内, 不污染导出的群智规则包。
//
// ── 接入现有文件所需的最小改动(共 4 处, 约 18 行)──────────────────────────────
//
//  1. fp_learn.go: fpEntry 增加可选字段(omitempty 保持旧 JSON 完全兼容):
//     PersonalTier string `json:"personal_tier,omitempty"` // exclusive | vendor_family | provisional | generic_stack
//     PersonalExp  int64  `json:"personal_exp,omitempty"`  // 快速蒸馏过期 unix(默认 +7 天)
//     PersonalSNIs int    `json:"personal_snis,omitempty"` // 本机真值验证过的独立域名数
//     并在 (e *fpEntry) verdict(now int64) 末尾 return 前调用:
//     e.applyPersonalVerdict(&v, now)
//
//  2. startup_fp.go: startupApp 增加可选字段:
//     PersonalFast bool  `json:"personal_fast,omitempty"`
//     PersonalExp  int64 `json:"personal_exp,omitempty"`
//     并在 buildStartupModel 过滤条件处调用 startupAppUsableFast(a, ma, shared, hiddenToks, now)。
//
//  3. action.go: switch action 增加:
//     case "dpi_distill_now":
//     return actionDPIDistillNow(s, p)
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── 单机快速蒸馏参数常量 ──────────────────────────────────────────────

const (
	// 协议栈分类枚举
	fpTierExclusive   = "exclusive"     // 高置信度单一 App 专属栈(立即参与无域名连接归属)
	fpTierVendorFam   = "vendor_family" // 同公司多 App 共用栈(如 TTNet/mars, 不绑单一 App)
	fpTierProvisional = "provisional"   // 待对照验证(纯 TCP h2 尚缺其它 App 背景对照)
	fpTierGeneric     = "generic_stack" // Android WebView / Chrome / 通用 OkHttp·Cronet(主动熔断)

	// 样本门槛(按协议栈特异性分级, 替代群智一刀切的 Support >= 50)
	distillMinSamplesCustomALPN = 3 // 自定义非标 ALPN(如 mmtls / ttnet 等)最小真值样本数
	distillMinSNIsCustomALPN    = 2 // 自定义 ALPN 至少命中 2 个独立目标(SNI 或远端 IP)

	distillMinSamplesQTP  = 4 // QUIC + QTP(12 项传输参数哈希)最小真值样本数
	distillMinSNIsQTP     = 2 // QUIC + QTP 至少命中 2 个独立目标
	distillMinPoolAppsQTP = 2 // 样本池至少出现过 2 个不同应用, 排除完全未改默认参数的裸 Cronet

	distillMinSamplesStdTCP    = 6  // 标准 TCP TLS(h2 / http/1.1 / 空 ALPN, 无 QTP)最小真值样本数
	distillMinSNIsStdTCP       = 3  // 标准 TCP TLS 至少命中 3 个独立业务域名
	distillMinContrastAppsTCP  = 3  // 背景对照组门控: 样本池至少测过 3 个不同应用
	distillMinContrastOtherSmp = 10 // 背景对照组门控: 其它应用合计至少 10 条样本, 确保系统 WebView/OkHttp 已暴露

	// 主导率(纯度)与置信度上限
	distillMinPurityCustomOrQTP = 0.95 // 自定义 ALPN / QTP 允许极少量噪声(>= 95%)
	distillMinPurityStdTCP      = 1.00 // 标准 TCP TLS 必须 100% 纯净(零其它应用、零热点 _other)
	distillGenericOtherShare    = 0.10 // 其它应用或 _other 占比 >= 10% 即撤回专属资格
	distillMaxConfCustomALPN    = 0.78 // 低于 rulepackMinFPConf(0.80), 天然隔离不进导出规则包
	distillMaxConfQTP           = 0.76
	distillMaxConfStdTCP        = 0.72
	distillTTLSec               = 7 * 24 * 3600 // 单机快速蒸馏加成有效期 7 天(期满未转正自动回落常规门槛)

	// 冷启动序列快速蒸馏参数(替代常规 30min 周期 + 600s 间隔 + 3 次启动)
	distillStartupGapSec        = 45   // 集中测试静默切分间隔: 45 秒(原 startupGapSec = 600s)
	distillStartupFGCooldownSec = 25   // 结合 self_fg 前台切换切分时的最小防抖间隔: 25 秒
	distillStartupMinStartsFG   = 1.0  // 有前台真值佐证 + >= 3 个严格独占非 SDK 特征 token 时: 1 次冷启动即可用
	distillStartupMinStartsFast = 2.0  // 无前台切换记录但 >= 2 个严格独占非 SDK 特征 token 时: 2 次冷启动可用
	distillStartupFeatFreq      = 0.67 // 小样本下特征 token 出现频率下限(1/1=1.0, 2/2=1.0, 2/3=0.67)
	distillStartupMaxSharedApps = 1    // 快速蒸馏特征 token 必须 100% 单应用独占(原 startupFeatMaxApps = 2)

	// 蒸馏窗口与状态文件
	distillDefaultLookbackDays = 7
	distillMaxReadLines        = 200000
	distillLocalDevTag         = "self_local"
)

// ─── 先验知识库: Android 系统 WebView / 浏览器 / 通用栈识别 ──────────────

// distillBrowserWebViewPkgs 本机一旦观察到这些包发出的 (JA4, ALPN, Port, QTP),
// 立即将该指纹打标为 generic_stack, 彻底阻断任何单一业务 App 认领。
var distillBrowserWebViewPkgs = map[string]bool{
	// Android System WebView / Chromium 内核提供者
	"com.google.android.webview":          true,
	"com.android.webview":                 true,
	"com.huawei.webview":                  true,
	"org.chromium.webview_shell":          true,
	"com.google.android.trichromelibrary": true,
	// 主流移动浏览器与内置搜索容器
	"com.android.chrome":           true,
	"com.chrome.beta":              true,
	"com.chrome.dev":               true,
	"com.chrome.canary":            true,
	"org.mozilla.firefox":          true,
	"org.mozilla.fenix":            true,
	"com.microsoft.emmx":           true,
	"com.opera.browser":            true,
	"com.brave.browser":            true,
	"com.vivaldi.browser":          true,
	"com.kiwibrowser.browser":      true,
	"com.UCMobile":                 true,
	"com.quark.browser":            true,
	"com.tencent.mtt":              true,
	"com.baidu.searchbox":          true,
	"com.heytap.browser":           true,
	"com.coloros.browser":          true,
	"com.vivo.browser":             true,
	"com.mi.globalbrowser":         true,
	"com.android.browser":          true,
	"com.huawei.browser":           true,
	"com.sec.android.app.sbrowser": true,
	"mark.via":                     true,
}

// distillBuiltinConduitPkgs VPN / 代理导管包(与 dpid builtinFlywheelExcludePkgs 对齐):
// 导管会代发全机所有 App 的连接, 绝不能参与指纹归属。
var distillBuiltinConduitPkgs = map[string]bool{
	"com.follow.clash":                     true,
	"com.github.kr328.clash":               true,
	"com.github.metacubex.clash.meta":      true,
	"com.v2ray.ang":                        true,
	"com.v2ray.actinium":                   true,
	"io.nekohasekai.sfa":                   true,
	"io.nekohasekai.sagernet":              true,
	"moe.nb4a":                             true,
	"moe.matsuri.lite":                     true,
	"com.github.shadowsocks":               true,
	"io.github.trojan_gfw.igniter":         true,
	"com.getsurfboard":                     true,
	"com.hiddify.hiddify":                  true,
	"app.hiddify.com":                      true,
	"com.wireguard.android":                true,
	"net.openvpn.openvpn":                  true,
	"de.blinkt.openvpn":                    true,
	"org.torproject.android":               true,
	"com.tailscale.ipn":                    true,
	"net.mullvad.mullvadvpn":               true,
	"org.outline.android.client":           true,
	"ch.protonvpn.android":                 true,
	"com.nordvpn.android":                  true,
	"com.expressvpn.vpn":                   true,
	"com.windscribe.vpn":                   true,
	"com.surfshark.vpnclient.android":      true,
	"com.cloudflare.onedotonedotonedotone": true,
	"eu.faircode.netguard":                 true,
	"com.celzero.bravedns":                 true,
	"com.adguard.android":                  true,
}

// distillStockCipherHashes Chromium/Android System WebView(BoringSSL)与 AOSP 默认
// Conscrypt(OkHttp 默认栈)最典型的 JA4 第二段(密码套件排序哈希)。
// 当无 QTP 且 ALPN 为常规 h2/http1.1 时, 命中这些套件哈希的一律禁止在小样本下升格为 exclusive。
var distillStockCipherHashes = map[string]bool{
	"8daaf6152771": true, // Chromium / Android System WebView / 标准 BoringSSL 15~17 套件族
	"5b57614c22b0": true, // Apple WebKit / Network.framework 标准套件族
	"acb858a92679": true, // Android Conscrypt / 标准 OkHttp 4.x TLS 1.3+1.2 默认套件族
	"e5627efa2ab1": true, // Android Conscrypt 精简套件族
}

// distillStdALPNs 常规 HTTP ALPN 集合; 不在此集合内的非空 ALPN 视为应用自定义协议栈信号。
func isStandardALPN(alpn string) bool {
	switch strings.ToLower(strings.TrimSpace(alpn)) {
	case "", "h2", "http/1.1", "http/1.0", "h3", "h3-29", "hq-interop":
		return true
	}
	return false
}

func ja4CipherHashPart(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// wireStackKind 根据 (JA4, ALPN, QTP) 判定传输层指纹的天然特异性等级。
func wireStackKind(ja4, alpn, qtp string, seedBrowserJA4 map[string]bool) string {
	if seedBrowserJA4[ja4] {
		return "stock_browser_seed"
	}
	if alpn != "" && !isStandardALPN(alpn) {
		return "custom_alpn"
	}
	if qtp != "" {
		return "quic_qtp"
	}
	if distillStockCipherHashes[ja4CipherHashPart(ja4)] {
		return "stock_webview_or_conscrypt"
	}
	return "std_tcp_tls"
}

// ─── 幂等增量状态持久化 (data/fp_distill_state.json) ─────────────────

type fpDistillState struct {
	Schema        int           `json:"schema"`
	SavedAt       int64         `json:"saved_at"`
	FPCursor      startupCursor `json:"fp_cursor"`      // fpStore 摄入 label_samples 的幂等偏移
	StartupCursor startupCursor `json:"startup_cursor"` // 快速冷启动切分的幂等偏移
}

func fpDistillStatePath(hncDir string) string {
	return filepath.Join(hncDir, "data", "fp_distill_state.json")
}

func loadFPDistillState(hncDir string) fpDistillState {
	b, err := os.ReadFile(fpDistillStatePath(hncDir))
	if err != nil || len(b) > 64<<10 {
		return fpDistillState{Schema: 1}
	}
	var st fpDistillState
	if json.Unmarshal(b, &st) != nil {
		return fpDistillState{Schema: 1}
	}
	return st
}

func saveFPDistillState(hncDir string, st fpDistillState) error {
	st.Schema = 1
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(fpDistillStatePath(hncDir), b)
}

var distillMu sync.Mutex

// ─── 请求参数与返回结构 ───────────────────────────────────────────────

type DistillOptions struct {
	LookbackDays     int  `json:"lookback_days,omitempty"`      // 回看最近几天样本(默认 7, 最小 1)
	AllowUnmappedPkg bool `json:"allow_unmapped_pkg,omitempty"` // 包名不在 pkg_app_map 时是否按规则命中自动归并(默认 true)
}

type DistillFPItem struct {
	JA4       string   `json:"ja4"`
	ALPN      string   `json:"alpn,omitempty"`
	PortClass string   `json:"port_class"`
	QTP       string   `json:"qtp,omitempty"`
	WireKind  string   `json:"wire_kind"` // custom_alpn | quic_qtp | std_tcp_tls | stock_webview_or_conscrypt
	Tier      string   `json:"tier"`      // exclusive | vendor_family | provisional | generic_stack
	AppID     string   `json:"app_id,omitempty"`
	AppName   string   `json:"app_name,omitempty"`
	Samples   int      `json:"samples"`
	UniqueSNI int      `json:"unique_sni"`
	Purity    float64  `json:"purity"`
	Conf      float64  `json:"conf,omitempty"`
	SharedBy  []string `json:"shared_by,omitempty"`
	Reason    string   `json:"reason"`
}

type DistillStartupItem struct {
	AppID        string   `json:"app_id"`
	AppName      string   `json:"app_name"`
	Starts       float64  `json:"starts"`
	FGVerified   bool     `json:"fg_verified"`
	FeatTokens   []string `json:"feat_tokens"`
	Usable       bool     `json:"usable"`
	StatusReason string   `json:"reason"`
}

type DistillReport struct {
	OK               bool                 `json:"ok"`
	DistilledAt      int64                `json:"distilled_at"`
	SamplesScanned   int                  `json:"samples_scanned"`
	NewFPSamplesFed  int                  `json:"new_fp_samples_fed"`
	DistinctAppsSeen int                  `json:"distinct_apps_seen"`
	ContrastReadyTCP bool                 `json:"contrast_ready_tcp"`
	ExclusiveCount   int                  `json:"exclusive_count"`
	VendorFamCount   int                  `json:"vendor_family_count"`
	ProvisionalCount int                  `json:"provisional_count"`
	GenericBlocked   int                  `json:"generic_blocked_count"`
	StartupUsable    int                  `json:"startup_usable_count"`
	UnmappedPkgs     []string             `json:"unmapped_pkgs,omitempty"`
	Fingerprints     []DistillFPItem      `json:"fingerprints"`
	Startups         []DistillStartupItem `json:"startups"`
	Hints            []string             `json:"hints,omitempty"`
}

// ─── fpEntry 与 startupModel 的最小判定钩子 ───────────────────────────

// applyPersonalVerdict 供 (e *fpEntry) verdict(now int64) 在常规判定后调用:
//   - generic_stack: 即使样本 < 20 也立即标 Generic = true, 拦截种子表与手工误绑;
//   - exclusive(有效期内): 实时重验当前 Purity(一旦后续混入其它 App 或 _other 立即自动失效)。
func (e *fpEntry) applyPersonalVerdict(v *fpVerdict, now int64) {
	if e == nil || v == nil || e.PersonalTier == "" {
		return
	}
	if e.PersonalTier == fpTierGeneric {
		v.Usable = false
		v.Generic = true
		v.Conf = 0
		return
	}
	if v.Usable || e.PersonalTier != fpTierExclusive || (e.PersonalExp > 0 && now > e.PersonalExp) {
		return
	}
	// 实时核验: 后续若出现任何第二个应用或热点 _other 稀释了纯度, 当场熔断撤回!
	minPurity := distillMinPurityCustomOrQTP
	minSup := float64(distillMinSamplesQTP)
	maxConf := distillMaxConfQTP
	switch {
	case e.ALPN != "" && !isStandardALPN(e.ALPN):
		minSup = float64(distillMinSamplesCustomALPN)
		maxConf = distillMaxConfCustomALPN
	case e.QTP == "":
		minPurity = distillMinPurityStdTCP
		minSup = float64(distillMinSamplesStdTCP)
		maxConf = distillMaxConfStdTCP
	}
	if v.Top == "" || v.Top == fpOtherApp || v.Purity < minPurity || v.Support < minSup*0.8 {
		return
	}
	v.Usable = true
	v.Generic = false
	v.Conf = math.Min(maxConf, v.Purity*v.Support/(v.Support+3.0))
}

// ─── 核心同步入口: DistillPersonalNow ─────────────────────────────────

// DistillPersonalNow 供 WebUI「立即蒸馏」按钮同步调用:
//  1. 增量把未消费的 label_samples 喂入 fpStore(幂等, 不重复计数);
//  2. 联合全量窗口样本 + 热点现有 fpStore 条目做五层协议栈解耦与防 WebView 误判分级;
//  3. 结合 self_fg 前台切换真值 + 45s 短间隔做冷启动序列快速切分与去 SDK 蒸馏;
//  4. 立即原子落盘 fp_learned.json / startup_fp.json / fp_distill_state.json, 并清空 dpi_eval 缓存。
func (s *server) DistillPersonalNow(now time.Time, opt DistillOptions) (DistillReport, error) {
	distillMu.Lock()
	defer distillMu.Unlock()

	if opt.LookbackDays <= 0 || opt.LookbackDays > 7 {
		opt.LookbackDays = distillDefaultLookbackDays
	}
	rep := DistillReport{
		OK:           true,
		DistilledAt:  now.Unix(),
		Fingerprints: []DistillFPItem{},
		Startups:     []DistillStartupItem{},
	}

	hncDir := s.hncDir
	// 1. 先同步吃进热点侧最新的 dpi_flows.json, 确保热点侧浏览器 _other 负样本最新
	fpSt := fpFor(hncDir)
	freshFlows := fpSt.tick(now, s.loadIPNames())
	sfp := startupFor(hncDir)
	sfp.observe(freshFlows, now)

	// 2. 加载映射表、规则元数据、导管排除表与内置浏览器 JA4 种子
	pmap := pkgAppMap(hncDir)
	rnames, hiddenRules := ruleMeta(hncDir)
	cat := loadAppCatalog(hncDir)
	conduitPkgs := buildConduitPkgSet(hncDir)
	seedBrowserJA4 := loadBrowserSeedJA4(hncDir)
	dstState := loadFPDistillState(hncDir)

	// 3. 读取窗口内全量 label_samples(用于全局协议栈纯度与对照分析) + 增量游标切分
	allSamples, newFPSamples, nextFPCursor := readDistillLabelSamples(hncDir, opt.LookbackDays, dstState.FPCursor, now)
	rep.SamplesScanned = len(allSamples)

	// 4. 构建 pkg → (appID, appName, category) 解析器(兼容未录入 pkg_app_map 的单应用自研域名自动推断)
	pkgResolver, unmapped := buildPkgAppResolver(allSamples, pmap, rnames, hiddenRules, conduitPkgs, cat, opt.AllowUnmappedPkg)
	rep.UnmappedPkgs = unmapped

	// 5. 聚合全窗口 (JA4, ALPN, Port, QTP) 多源证据
	pool := analyzePersonalFPPool(allSamples, pkgResolver, hiddenRules, conduitPkgs, seedBrowserJA4)
	rep.DistinctAppsSeen = len(pool.appSampleCounts)
	rep.ContrastReadyTCP = len(pool.appSampleCounts) >= distillMinContrastAppsTCP

	// 6. 将增量样本幂等写入 fpStore, 并对全部候选 key 打上安全分层标记 + 立即原子落盘
	fed, items := applyFPDistillToStore(fpSt, newFPSamples, pool, pkgResolver, hiddenRules, conduitPkgs, now)
	rep.NewFPSamplesFed = fed
	rep.Fingerprints = items
	for _, it := range items {
		switch it.Tier {
		case fpTierExclusive:
			rep.ExclusiveCount++
		case fpTierVendorFam:
			rep.VendorFamCount++
		case fpTierProvisional:
			rep.ProvisionalCount++
		case fpTierGeneric:
			rep.GenericBlocked++
		}
	}

	// 7. 冷启动序列快速蒸馏: 融合 self_fg 前台切换真值 + 45s 短间隔 + 剔除广告/CDN SDK token
	fgEvents := loadRecentSelfFG(hncDir, opt.LookbackDays, now)
	stItems, stUsable, nextStCursor := distillStartupSequences(
		sfp, allSamples, fgEvents, dstState.StartupCursor, nextFPCursor, pkgResolver, hiddenRules, now,
	)
	rep.Startups = stItems
	rep.StartupUsable = stUsable

	// 8. 保存幂等游标并刷新 dpi_eval 缓存, 让前端刷新自评页立即可见提升
	dstState.SavedAt = now.Unix()
	dstState.FPCursor = nextFPCursor
	dstState.StartupCursor = nextStCursor
	_ = saveFPDistillState(hncDir, dstState)
	dpiEvalCache.Store(dpiEvalResult{})
	_ = os.Remove(dpiEvalPath(hncDir))

	// 9. 生成面向用户的可解释诊断建议
	rep.Hints = buildDistillHints(rep)
	return rep, nil
}

// ─── HTTP / Action 导出接口 ───────────────────────────────────────────

// actionDPIDistillNow 供 POST /api/action {"action":"dpi_distill_now"} 同步调用。
func actionDPIDistillNow(s *server, p map[string]string) actionResp {
	days := distillDefaultLookbackDays
	if v := strings.TrimSpace(p["days"]); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 7 {
			days = n
		}
	}
	allowUnmapped := p["allow_unmapped"] != "false"
	rep, err := s.DistillPersonalNow(time.Now(), DistillOptions{
		LookbackDays:     days,
		AllowUnmappedPkg: allowUnmapped,
	})
	if err != nil {
		return actionResp{OK: false, Error: "distill failed", Detail: err.Error()}
	}
	b, _ := json.Marshal(rep)
	return actionResp{OK: true, Detail: string(b)}
}

// ─── 内部实现: 样本读取与包名归并 ─────────────────────────────────────

type distillSample struct {
	evalSample
	date string
}

func readDistillLabelSamples(hncDir string, days int, cur startupCursor, now time.Time) (all, incremental []distillSample, next startupCursor) {
	files := startupSampleFiles(filepath.Join(hncDir, "run"))
	cutoff := now.Local().AddDate(0, 0, -(days - 1)).Format("20060102")
	dates := make([]string, 0, len(files))
	for d := range files {
		if d >= cutoff {
			dates = append(dates, d)
		}
	}
	sort.Strings(dates)
	next = cur
	rem := distillMaxReadLines
	for _, d := range dates {
		if rem <= 0 {
			break
		}
		path := files[d]
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		// 若样本文件被清除重建(size < 游标), 重置当天游标
		incOff := int64(0)
		if d == cur.Date {
			if fi.Size() >= cur.Offset {
				incOff = cur.Offset
			}
		} else if d < cur.Date {
			incOff = fi.Size() // 已消费过的历史天不再增量喂入
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		br := bufio.NewReaderSize(f, 32<<10)
		var off int64
		for rem > 0 {
			line, rerr := br.ReadSlice('\n')
			if rerr != nil {
				break
			}
			lineLen := int64(len(line))
			prevOff := off
			off += lineLen
			rem--
			if len(line) > startupMaxLineBytes {
				continue
			}
			var s evalSample
			if json.Unmarshal(line, &s) != nil || s.Pkg == "" || s.Ts <= 0 || s.UID < startupMinUID {
				continue
			}
			ds := distillSample{evalSample: s, date: d}
			all = append(all, ds)
			if d > cur.Date || (d == cur.Date && prevOff >= incOff) {
				incremental = append(incremental, ds)
			}
		}
		_ = f.Close()
		if d >= next.Date {
			next = startupCursor{Date: d, Offset: off}
		}
	}
	return all, incremental, next
}

type resolvedPkgApp struct {
	ID       string
	Name     string
	Category string
	Vendor   string // 用于识别同公司多 App 共享网络栈(如 com.ss.android.* / com.miHoYo.*)
}

func buildConduitPkgSet(hncDir string) map[string]bool {
	out := make(map[string]bool, len(distillBuiltinConduitPkgs)+8)
	for k := range distillBuiltinConduitPkgs {
		out[k] = true
	}
	for _, p := range loadFlywheelExcludeUser(hncDir) {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = true
		}
	}
	return out
}

func loadBrowserSeedJA4(hncDir string) map[string]bool {
	out := map[string]bool{}
	var b []byte
	var err error
	for _, cand := range dataCandidates(hncDir, "dpi_ja4_fingerprints.json") {
		if b, err = os.ReadFile(cand); err == nil && len(b) > 0 {
			break
		}
	}
	if err != nil || len(b) == 0 || len(b) > 512<<10 {
		return out
	}
	var f struct {
		Fingerprints []struct {
			JA4      string `json:"ja4"`
			Category string `json:"category"`
		} `json:"fingerprints"`
	}
	if json.Unmarshal(b, &f) != nil {
		return out
	}
	for _, fp := range f.Fingerprints {
		if strings.EqualFold(fp.Category, "browser") && fp.JA4 != "" {
			out[fp.JA4] = true
		}
	}
	return out
}

func pkgVendorKey(pkg, appID string) string {
	// 优先复用常见大厂家族归属, 避免同厂双端(如抖音+头条共用 TTNet)被误判成系统 WebView,
	// 同时仍阻止把同厂共享栈绑死在单个子应用上。
	parts := strings.Split(strings.ToLower(pkg), ".")
	if len(parts) >= 2 {
		p2 := parts[0] + "." + parts[1]
		switch p2 {
		case "com.ss", "com.bytedance":
			return "bytedance"
		case "com.tencent":
			return "tencent"
		case "com.alibaba", "com.taobao", "com.autonavi", "com.amap":
			return "alibaba"
		case "com.mihoyo", "com.hoyoverse":
			return "mihoyo"
		case "com.netease":
			return "netease"
		case "com.kuaishou", "com.smile":
			return "kuaishou"
		case "com.baidu":
			return "baidu"
		case "com.sankuai", "com.meituan":
			return "meituan"
		}
		if parts[0] != "com" && parts[0] != "org" && parts[0] != "net" && parts[0] != "cn" && parts[0] != "io" {
			return p2
		}
		if len(parts) >= 3 {
			return p2
		}
	}
	return appID
}

func isSystemROMNoisePkg(pkg string) bool {
	p := strings.ToLower(pkg)
	for _, pref := range []string{
		"com.android.", "android.", "com.google.android.gms", "com.google.android.gsf",
		"com.oplus.", "com.coloros.", "com.heytap.", "com.nearme.",
		"com.miui.", "com.xiaomi.finddevice", "com.vivo.abe", "com.huawei.hwid",
	} {
		if strings.HasPrefix(p, pref) {
			return true
		}
	}
	return false
}

// buildPkgAppResolver 优先查 pkg_app_map.json; 若某第三方 App 尚未收录进 pkg_app_map,
// 但其本机非 SDK 流量稳定命中同一条现有业务规则(如某区域版/极速版包名), 则自动归并到该规则,
// 其余未映射第三方包记入 unmapped 列表提示用户。
func buildPkgAppResolver(
	samples []distillSample,
	pmap, rnames map[string]string,
	hiddenRules, conduitPkgs map[string]bool,
	cat *appCatalog,
	allowInfer bool,
) (map[string]resolvedPkgApp, []string) {
	res := map[string]resolvedPkgApp{}
	pkgRuleVotes := map[string]map[string]int{}
	seenPkgs := map[string]int{}

	for _, s := range samples {
		if distillBrowserWebViewPkgs[s.Pkg] || conduitPkgs[s.Pkg] || isSystemROMNoisePkg(s.Pkg) {
			continue
		}
		seenPkgs[s.Pkg]++
		if s.RuleID != "" && !hiddenRules[s.RuleID] {
			if pkgRuleVotes[s.Pkg] == nil {
				pkgRuleVotes[s.Pkg] = map[string]int{}
			}
			pkgRuleVotes[s.Pkg][s.RuleID]++
		}
	}

	var unmapped []string
	for pkg := range seenPkgs {
		appID := pmap[pkg]
		if appID == "" && allowInfer {
			// 若该包名 >= 80% 且 >= 3 条已识别业务域名都指向同一规则 ID, 自动关联
			votes := pkgRuleVotes[pkg]
			tot, bestID, bestN := 0, "", 0
			for id, n := range votes {
				tot += n
				if n > bestN {
					bestID, bestN = id, n
				}
			}
			if bestN >= 3 && float64(bestN)/float64(tot) >= 0.80 {
				appID = bestID
			}
		}
		if appID == "" {
			unmapped = append(unmapped, pkg)
			continue
		}
		name, category := rnames[appID], ""
		if cat != nil && cat.apps[appID] != nil {
			if name == "" {
				name = cat.apps[appID].Name
			}
			category = cat.apps[appID].Category
		}
		if name == "" {
			name = appID
		}
		if appTier(category) == tierHidden {
			continue
		}
		res[pkg] = resolvedPkgApp{
			ID:       appID,
			Name:     name,
			Category: category,
			Vendor:   pkgVendorKey(pkg, appID),
		}
	}
	sort.Strings(unmapped)
	return res, unmapped
}

// ─── 内部实现: 五层协议栈纯度与防 WebView 误判分析 ────────────────────

type fpKeyEvidence struct {
	ja4, alpn, port, qtp string
	wireKind             string
	browserTainted       bool
	browserPkgs          map[string]bool
	appCounts            map[string]int
	appNames             map[string]string
	appCats              map[string]string
	appVendors           map[string]string
	appSNIs              map[string]map[string]bool // appID → 独立业务端点集合(SNI 或 RIP)
	unmappedPkgs         map[string]int             // 未收录进 pkg_app_map 的其它独立 App 包名也作为负样本!
	totalValid           int
}

type personalFPPool struct {
	byKey           map[string]*fpKeyEvidence
	ja4BrowserTaint map[string]bool // 裸 JA4 曾在浏览器/WebView 出现过
	appSampleCounts map[string]int
	totalAppSamples int
}

func analyzePersonalFPPool(
	samples []distillSample,
	resolver map[string]resolvedPkgApp,
	hiddenRules, conduitPkgs, seedBrowserJA4 map[string]bool,
) *personalFPPool {
	pool := &personalFPPool{
		byKey:           map[string]*fpKeyEvidence{},
		ja4BrowserTaint: map[string]bool{},
		appSampleCounts: map[string]int{},
	}
	for _, s := range samples {
		if s.JA4 == "" || !dpiJA4RE.MatchString(s.JA4) || conduitPkgs[s.Pkg] {
			continue
		}
		port := fpPortClass(s.DPort)
		qtp := ""
		if s.QUIC {
			qtp = fpCleanQTP(s.QTP)
		}
		key := fpKeyQ(s.JA4, s.ALPN, port, qtp)
		ev := pool.byKey[key]
		if ev == nil {
			ev = &fpKeyEvidence{
				ja4: s.JA4, alpn: s.ALPN, port: port, qtp: qtp,
				wireKind:     wireStackKind(s.JA4, s.ALPN, qtp, seedBrowserJA4),
				browserPkgs:  map[string]bool{},
				appCounts:    map[string]int{},
				appNames:     map[string]string{},
				appCats:      map[string]string{},
				appVendors:   map[string]string{},
				appSNIs:      map[string]map[string]bool{},
				unmappedPkgs: map[string]int{},
			}
			pool.byKey[key] = ev
		}

		// 层 1: 系统 WebView / 浏览器包发出的任何指纹直接标记污染
		if distillBrowserWebViewPkgs[s.Pkg] {
			ev.browserTainted = true
			ev.browserPkgs[s.Pkg] = true
			if qtp == "" {
				pool.ja4BrowserTaint[s.JA4] = true
			}
			continue
		}
		if isSystemROMNoisePkg(s.Pkg) {
			// 系统 ROM 组件共用该栈也计入负样本, 防止业务 App 独占系统 Conscrypt 栈
			ev.unmappedPkgs["sys:"+s.Pkg]++
			ev.totalValid++
			continue
		}
		// 跳过纯第三方广告/CDN SDK 域名连接? 注意: 第三方 SDK 也是宿主 App 的网络栈发出的,
		// 但若两个不同 App 都内嵌穿山甲/友盟并用系统 OkHttp 发出, 保留它们恰恰能更快暴露通用 OkHttp 栈!
		// 因此这里保留其对栈共现的计数, 仅在统计「独立业务 SNI」时剔除 hiddenRules。
		rp, ok := resolver[s.Pkg]
		if !ok {
			ev.unmappedPkgs[s.Pkg]++
			ev.totalValid++
			continue
		}
		ev.appCounts[rp.ID]++
		ev.appNames[rp.ID] = rp.Name
		ev.appCats[rp.ID] = rp.Category
		ev.appVendors[rp.ID] = rp.Vendor
		ev.totalValid++
		pool.appSampleCounts[rp.ID]++
		pool.totalAppSamples++

		if !hiddenRules[s.RuleID] {
			if ev.appSNIs[rp.ID] == nil {
				ev.appSNIs[rp.ID] = map[string]bool{}
			}
			ep := strings.ToLower(strings.TrimSpace(s.SNI))
			if ep == "" {
				ep = s.RIP
			}
			if ep != "" {
				ev.appSNIs[rp.ID][ep] = true
			}
		}
	}
	return pool
}

// classifyKeyWithStore 融合本机真值池(pool)与热点现有学习表(stEntry)给出最终四档裁决。
func classifyKeyWithStore(ev *fpKeyEvidence, stEntry *fpEntry, pool *personalFPPool, now int64) DistillFPItem {
	it := DistillFPItem{
		JA4:       ev.ja4,
		ALPN:      ev.alpn,
		PortClass: ev.port,
		QTP:       ev.qtp,
		WireKind:  ev.wireKind,
	}

	// 汇总所有共现主体(本机已映射 App + 本机未映射包 + 热点学习表已有 App/_other)
	combined := map[string]float64{}
	sharedNames := map[string]bool{}
	for id, n := range ev.appCounts {
		combined[id] += float64(n)
		sharedNames[ev.appNames[id]] = true
	}
	for pkg, n := range ev.unmappedPkgs {
		combined["pkg:"+pkg] += float64(n)
		sharedNames[pkg] = true
	}
	if stEntry != nil {
		f := fpDecayFactor(stEntry.Upd, now)
		for id, ac := range stEntry.Apps {
			// 热点学习表里的 _other(浏览器访问未知站点)或其它应用作为强负样本并入
			if _, alreadyInLocal := ev.appCounts[id]; !alreadyInLocal {
				combined[id] += ac.N * f
				if id == fpOtherApp {
					sharedNames["热点未知站点(_other)"] = true
				} else if ac.Name != "" {
					sharedNames[ac.Name] = true
				} else {
					sharedNames[id] = true
				}
			}
		}
	}

	var tot, topN float64
	topID := ""
	for id, v := range combined {
		tot += v
		if v > topN || (v == topN && id < topID) {
			topN, topID = v, id
		}
	}
	if tot > 0 {
		it.Purity = round2(topN / tot)
	}
	if topID != "" && !strings.HasPrefix(topID, "pkg:") && topID != fpOtherApp {
		it.AppID = topID
		it.AppName = ev.appNames[topID]
		it.Samples = ev.appCounts[topID]
		it.UniqueSNI = len(ev.appSNIs[topID])
	}
	for nm := range sharedNames {
		it.SharedBy = append(it.SharedBy, nm)
	}
	sort.Strings(it.SharedBy)

	// ── 裁决 1: 浏览器 / 系统 WebView 直接污染或内置浏览器种子命中 ──
	if ev.browserTainted || (ev.qtp == "" && pool.ja4BrowserTaint[ev.ja4]) || ev.wireKind == "stock_browser_seed" {
		it.Tier = fpTierGeneric
		it.Reason = "本机浏览器或 Android System WebView 曾使用该 TLS 指纹，已熔断防误判"
		return it
	}

	// ── 裁决 2: 多主体共现(跨应用纯度不足) ──
	distinctEntities := len(combined)
	if topID == fpOtherApp || strings.HasPrefix(topID, "pkg:") {
		if tot >= 2 {
			it.Tier = fpTierGeneric
			it.Reason = "主要由未知站点(_other)或系统/未映射包共用，判定为通用网络栈"
		} else {
			it.Tier = fpTierProvisional
			it.Reason = "应用包名尚未建立规则映射，暂不启用"
		}
		return it
	}

	if distinctEntities >= 2 && (tot-topN)/tot >= distillGenericOtherShare {
		// 检查是否全部来自同一大厂家族(如抖音+今日头条共用 TTNet)
		sameVendor := len(ev.unmappedPkgs) == 0 && combined[fpOtherApp] == 0
		vendor := ev.appVendors[topID]
		if sameVendor && vendor != "" {
			for id := range combined {
				if v2 := ev.appVendors[id]; v2 == "" || v2 != vendor {
					sameVendor = false
					break
				}
			}
		} else {
			sameVendor = false
		}
		if sameVendor {
			it.Tier = fpTierVendorFam
			it.Reason = fmt.Sprintf("同厂商多款应用(%s)共享同一自研网络栈，保留家族线索但不绑单一应用", strings.Join(it.SharedBy, " / "))
			return it
		}
		it.Tier = fpTierGeneric
		it.Reason = fmt.Sprintf("被 %d 个不同来源共用(%s)，属于通用 OkHttp/Cronet/WebView 网络栈", distinctEntities, strings.Join(it.SharedBy, "、"))
		return it
	}

	// ── 裁决 3: Chromium / Conscrypt 标准套件哈希无 QTP 保护 ──
	if ev.wireKind == "stock_webview_or_conscrypt" {
		it.Tier = fpTierGeneric
		it.Reason = "命中 Chromium/WebView 或 Android Conscrypt 默认 TLS 套件哈希且无定制 ALPN/QTP，禁止绑定单一应用"
		return it
	}

	// ── 裁决 4: 单一应用高纯度候选 —— 按协议栈特异性核验样本量与背景对照门控 ──
	purityRaw := 0.0
	if tot > 0 {
		purityRaw = topN / tot
	}
	switch ev.wireKind {
	case "custom_alpn":
		if it.Samples >= distillMinSamplesCustomALPN && it.UniqueSNI >= distillMinSNIsCustomALPN && purityRaw >= distillMinPurityCustomOrQTP {
			it.Tier = fpTierExclusive
			it.Conf = round2(math.Min(distillMaxConfCustomALPN, purityRaw*float64(it.Samples)/float64(it.Samples+3)))
			it.Reason = fmt.Sprintf("自定义专属 ALPN(%s) + %d 个独立端点验证通过", ev.alpn, it.UniqueSNI)
			return it
		}
		it.Tier = fpTierProvisional
		it.Reason = fmt.Sprintf("自定义 ALPN 样本尚少(当前 %d 条/%d 域名，需 >= %d 条/%d 域名)",
			it.Samples, it.UniqueSNI, distillMinSamplesCustomALPN, distillMinSNIsCustomALPN)
		return it

	case "quic_qtp":
		if len(pool.appSampleCounts) < distillMinPoolAppsQTP {
			it.Tier = fpTierProvisional
			it.Reason = "QUIC+QTP 纯度达标，请再顺手打开至少 1 个其它常用 App 对照以排除默认 Cronet 参数"
			return it
		}
		if it.Samples >= distillMinSamplesQTP && it.UniqueSNI >= distillMinSNIsQTP && purityRaw >= distillMinPurityCustomOrQTP {
			it.Tier = fpTierExclusive
			it.Conf = round2(math.Min(distillMaxConfQTP, purityRaw*float64(it.Samples)/float64(it.Samples+3)))
			it.Reason = fmt.Sprintf("QUIC 定制传输参数(%s) + %d 个独立域名高纯度通过", ev.qtp, it.UniqueSNI)
			return it
		}
		it.Tier = fpTierProvisional
		it.Reason = fmt.Sprintf("QUIC+QTP 样本尚少(当前 %d 条/%d 域名，需 >= %d 条/%d 域名)",
			it.Samples, it.UniqueSNI, distillMinSamplesQTP, distillMinSNIsQTP)
		return it

	default: // std_tcp_tls
		otherSamples := pool.totalAppSamples - pool.appSampleCounts[topID]
		if len(pool.appSampleCounts) < distillMinContrastAppsTCP || otherSamples < distillMinContrastOtherSmp {
			it.Tier = fpTierProvisional
			it.Reason = fmt.Sprintf(
				"常规 TCP TLS(当前已测 %d 个应用/其它应用 %d 条样本)；需至少测 %d 个应用且对照组 >= %d 条样本以排除系统 WebView/OkHttp",
				len(pool.appSampleCounts), otherSamples, distillMinContrastAppsTCP, distillMinContrastOtherSmp,
			)
			return it
		}
		if it.Samples >= distillMinSamplesStdTCP && it.UniqueSNI >= distillMinSNIsStdTCP && purityRaw >= distillMinPurityStdTCP {
			it.Tier = fpTierExclusive
			it.Conf = round2(math.Min(distillMaxConfStdTCP, purityRaw*float64(it.Samples)/float64(it.Samples+3)))
			it.Reason = fmt.Sprintf("经 %d 个应用背景对照验证，100%% 独占 TCP TLS 栈(%d 域名)", len(pool.appSampleCounts), it.UniqueSNI)
			return it
		}
		it.Tier = fpTierProvisional
		it.Reason = fmt.Sprintf("常规 TCP TLS 需 >= %d 条样本、>= %d 个独立业务域名且 100%% 纯净(当前 %d 条/%d 域名)",
			distillMinSamplesStdTCP, distillMinSNIsStdTCP, it.Samples, it.UniqueSNI)
		return it
	}
}

func applyFPDistillToStore(
	fpSt *fpStore,
	newSamples []distillSample,
	pool *personalFPPool,
	resolver map[string]resolvedPkgApp,
	hiddenRules, conduitPkgs map[string]bool,
	now time.Time,
) (int, []DistillFPItem) {
	ts := now.Unix()
	exp := ts + distillTTLSec
	devHash := fpDevKey(distillLocalDevTag)

	fpSt.mu.Lock()
	defer fpSt.mu.Unlock()
	fpSt.loadLocked()

	// 1. 增量把尚未入库的本机真值样本喂进 fpStore(幂等, 真实样本权重 1.0)
	fed := 0
	for _, s := range newSamples {
		if s.JA4 == "" || !dpiJA4RE.MatchString(s.JA4) || conduitPkgs[s.Pkg] {
			continue
		}
		port := fpPortClass(s.DPort)
		qtp := ""
		if s.QUIC {
			qtp = fpCleanQTP(s.QTP)
		}
		key := fpKeyQ(s.JA4, s.ALPN, port, qtp)
		e := fpSt.m[key]
		if e == nil {
			e = &fpEntry{JA4: s.JA4, ALPN: s.ALPN, Port: port, QTP: qtp, Upd: s.Ts}
			fpSt.m[key] = e
		}
		lt := s.Ts
		if lt <= 0 || lt > ts {
			lt = ts
		}
		if distillBrowserWebViewPkgs[s.Pkg] || isSystemROMNoisePkg(s.Pkg) {
			// 浏览器/系统 WebView 真值直接记入 _other, 从源头稀释通用指纹纯度
			e.learn(fpOtherApp, "", "", 1.0, devHash, lt)
			fed++
			fpSt.dirty = true
			continue
		}
		if hiddenRules[s.RuleID] {
			continue
		}
		if rp, ok := resolver[s.Pkg]; ok {
			e.learn(rp.ID, rp.Name, rp.Category, 1.0, devHash, lt)
			fed++
			fpSt.stats.FlowsLearned++
			fpSt.dirty = true
		}
	}

	// 2. 对全窗口内观察到的每个指纹 key 执行安全分层并更新 PersonalTier
	keys := make([]string, 0, len(pool.byKey))
	for k := range pool.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]DistillFPItem, 0, len(keys))
	for _, k := range keys {
		ev := pool.byKey[k]
		e := fpSt.m[k]
		it := classifyKeyWithStore(ev, e, pool, ts)
		items = append(items, it)
		if e == nil && it.Tier == fpTierGeneric {
			e = &fpEntry{JA4: ev.ja4, ALPN: ev.alpn, Port: ev.port, QTP: ev.qtp, Upd: ts, First: ts, Last: ts}
			e.learn(fpOtherApp, "", "", 1.0, devHash, ts)
			fpSt.m[k] = e
		}
		if e != nil {
			e.PersonalTier = it.Tier
			e.PersonalSNIs = it.UniqueSNI
			if it.Tier == fpTierExclusive {
				e.PersonalExp = exp
			} else {
				e.PersonalExp = 0
			}
			fpSt.dirty = true
		}
	}

	fpSt.evictEntriesLocked()
	if fpSt.dirty {
		_ = fpSt.saveLocked(now) // 不等 10 分钟 fpSaveEvery, 点击即刻原子写盘!
	}

	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := tierSortRank(items[i].Tier), tierSortRank(items[j].Tier)
		if ri != rj {
			return ri < rj
		}
		if items[i].Samples != items[j].Samples {
			return items[i].Samples > items[j].Samples
		}
		return items[i].JA4 < items[j].JA4
	})
	return fed, items
}

func tierSortRank(tier string) int {
	switch tier {
	case fpTierExclusive:
		return 0
	case fpTierVendorFam:
		return 1
	case fpTierProvisional:
		return 2
	default:
		return 3
	}
}

// ─── 内部实现: 冷启动多域名序列快速蒸馏 ───────────────────────────────

func loadRecentSelfFG(hncDir string, days int, now time.Time) []selfFGRecord {
	var out []selfFGRecord
	for i := days - 1; i >= 0; i-- {
		day := now.Local().AddDate(0, 0, -i).Format("20060102")
		f, err := os.Open(filepath.Join(hncDir, "run", "self_fg."+day+".jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		for sc.Scan() {
			var r selfFGRecord
			if json.Unmarshal(sc.Bytes(), &r) == nil && r.Pkg != "" && r.Ts > 0 {
				out = append(out, r)
			}
		}
		_ = f.Close()
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ts < out[j].Ts })
	return out
}

// fgSwitchTimesForPkg 提取某包从其它包切入前台的所有时刻(用于突破 600s 静默限制)。
func fgSwitchTimesForPkg(fg []selfFGRecord) map[string][]int64 {
	out := map[string][]int64{}
	prev := ""
	for _, r := range fg {
		if r.Pkg != prev {
			out[r.Pkg] = append(out[r.Pkg], r.Ts)
			prev = r.Pkg
		}
	}
	return out
}

func hasFGSwitchNear(switches []int64, ts int64) bool {
	// self_fg 探测间隔 10~60s, 因此前台切入记录可能在网络首包前 15s 至首包后 30s 落盘
	lo, hi := ts-15, ts+30
	idx := sort.Search(len(switches), func(i int) bool { return switches[i] >= lo })
	return idx < len(switches) && switches[idx] <= hi
}

// startupAppUsableFast 供 startup_fp.go buildStartupModel 兼容快速蒸馏条目:
// 常规模式仍要求 starts >= 3 && feat >= 2;
// 单机快速蒸馏有效期内, 允许 starts >= 1(有前台真值且 >= 3 个 100% 独占非 SDK token)
// 或 starts >= 2(>= 2 个 100% 独占非 SDK token)。
func startupAppUsableFast(a *startupApp, ma *startupModelApp, shared map[string]int, hiddenToks map[string]bool, now int64) bool {
	if ma.starts >= startupMinStarts && len(ma.feat) >= startupMinFeat {
		return true
	}
	if a == nil || !a.PersonalFast || (a.PersonalExp > 0 && now > a.PersonalExp) {
		return false
	}
	// 快速模式下收紧特征纯度: 只保留 shared[tok] == 1 且不属于公共广告/CDN SDK 的严格独占 token
	strict := map[string]float64{}
	sum := 0.0
	for tok, freq := range ma.feat {
		if shared[tok] <= distillStartupMaxSharedApps && !hiddenToks[tok] && freq >= distillStartupFeatFreq {
			strict[tok] = freq
			sum += freq
		}
	}
	if (ma.starts >= distillStartupMinStartsFG && len(strict) >= 3) ||
		(ma.starts >= distillStartupMinStartsFast && len(strict) >= 2) {
		ma.feat = strict
		ma.sumF = sum
		return true
	}
	return false
}

func distillStartupSequences(
	sfp *startupStore,
	allSamples []distillSample,
	fg []selfFGRecord,
	prevCur, nextCur startupCursor,
	resolver map[string]resolvedPkgApp,
	hiddenRules map[string]bool,
	now time.Time,
) ([]DistillStartupItem, int, startupCursor) {
	ts := now.Unix()
	exp := ts + distillTTLSec
	fgSwitches := fgSwitchTimesForPkg(fg)

	// 识别哪些 SNI token 来自广告/统计/CDN 隐藏类规则, 禁止在 1~2 次小样本冷启动里充当特征
	hiddenToks := map[string]bool{}
	for _, s := range allSamples {
		if hiddenRules[s.RuleID] {
			if tok := startupToken(s.SNI); tok != "" {
				hiddenToks[tok] = true
			}
		}
	}

	// 按 45s 短静默窗 或 self_fg 前台切换事件对本机样本做高灵敏度启动切分
	type ep struct {
		appID      string
		start      int64
		tokens     []string
		fgVerified bool
	}
	var episodes []ep
	openByPkg := map[string]*ep{}
	lastTsByPkg := map[string]int64{}
	lastStartByPkg := map[string]int64{}

	flushEp := func(pkg string) {
		o := openByPkg[pkg]
		if o == nil {
			return
		}
		delete(openByPkg, pkg)
		if len(o.tokens) >= startupMinTokens {
			episodes = append(episodes, *o)
		}
	}

	for _, s := range allSamples {
		rp, ok := resolver[s.Pkg]
		if !ok {
			continue
		}
		tok := startupToken(s.SNI)
		if tok == "" || hiddenToks[tok] {
			continue
		}
		if o := openByPkg[s.Pkg]; o != nil && s.Ts > o.start+startupWinSec {
			flushEp(s.Pkg)
		}
		if o := openByPkg[s.Pkg]; o != nil {
			if !containsStr(o.tokens, tok) && len(o.tokens) < startupMaxTokens {
				o.tokens = append(o.tokens, tok)
			}
		} else {
			last := lastTsByPkg[s.Pkg]
			fgHit := hasFGSwitchNear(fgSwitches[s.Pkg], s.Ts)
			gapOK := last == 0 || s.Ts-last >= distillStartupGapSec ||
				(fgHit && s.Ts-lastStartByPkg[s.Pkg] >= distillStartupFGCooldownSec)
			if gapOK {
				openByPkg[s.Pkg] = &ep{
					appID:      rp.ID,
					start:      s.Ts,
					tokens:     []string{tok},
					fgVerified: fgHit,
				}
				lastStartByPkg[s.Pkg] = s.Ts
			}
		}
		if s.Ts > lastTsByPkg[s.Pkg] {
			lastTsByPkg[s.Pkg] = s.Ts
		}
	}
	// 立即收尾已满 8 秒窗口的启动(无需像常规模式那样等 600 秒!)
	for pkg, o := range openByPkg {
		if ts-o.start >= startupWinSec {
			flushEp(pkg)
		}
	}

	// 聚合快速蒸馏视图并幂等补足 startupStore(不重复叠加已有常规计数)
	fastTable := newStartupTable()
	fgVerifiedApp := map[string]bool{}
	appNames := map[string]string{}
	for _, rp := range resolver {
		appNames[rp.ID] = rp.Name
	}
	for _, e := range episodes {
		fastTable.addStart(e.appID, appNames[e.appID], e.tokens, e.start, false)
		if e.fgVerified {
			fgVerifiedApp[e.appID] = true
		}
	}

	sfp.mu.Lock()
	sfp.loadLocked()
	// 将快速切分出的新增有效启动合并入持久化表(取 max 保证幂等, 绝不因多次点击翻倍)
	for id, fa := range fastTable.apps {
		cur := sfp.table.apps[id]
		if cur == nil {
			cpToks := make(map[string]float64, len(fa.Tokens))
			for t, n := range fa.Tokens {
				cpToks[t] = n
			}
			cur = &startupApp{
				AppID:  id,
				Name:   fa.Name,
				Starts: fa.Starts,
				Tokens: cpToks,
				Last:   fa.Last,
				Upd:    ts,
			}
			sfp.table.apps[id] = cur
		} else {
			cur.decayTo(ts)
			if fa.Name != "" {
				cur.Name = fa.Name
			}
			if fa.Starts > cur.Starts {
				cur.Starts = fa.Starts
			}
			for t, n := range fa.Tokens {
				if n > cur.Tokens[t] {
					cur.Tokens[t] = n
				}
			}
			if fa.Last > cur.Last {
				cur.Last = fa.Last
			}
		}
		cur.PersonalFast = true
		cur.PersonalExp = exp
	}
	sfp.stats.LastLearn = ts
	sfp.model = nil // 强制立即重建识别模型(不等 600s modelAt 缓存)

	// 计算跨应用 token 独占度并生成报告
	shared := map[string]int{}
	for _, a := range sfp.table.apps {
		f := startupDecay(a.Upd, ts)
		st := a.Starts * f
		if st <= 0 {
			continue
		}
		for tok, n := range a.Tokens {
			if n*f/st >= startupFeatFreq {
				shared[tok]++
			}
		}
	}
	for id, im := range sfp.importedLocked() {
		if _, mine := sfp.table.apps[id]; mine {
			continue
		}
		for tok, v := range im.Tokens {
			if v >= startupFeatFreq {
				shared[tok]++
			}
		}
	}

	ids := make([]string, 0, len(sfp.table.apps))
	for id := range sfp.table.apps {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []DistillStartupItem
	usableCount := 0
	for _, id := range ids {
		a := sfp.table.apps[id]
		f := startupDecay(a.Upd, ts)
		starts := a.Starts * f
		var strictFeats, regularFeats []string
		for tok, n := range a.Tokens {
			if starts <= 0 {
				continue
			}
			fr := math.Min(n*f/starts, 1.0)
			if fr >= startupFeatFreq && shared[tok] <= startupFeatMaxApps {
				regularFeats = append(regularFeats, tok)
			}
			if fr >= distillStartupFeatFreq && shared[tok] <= distillStartupMaxSharedApps && !hiddenToks[tok] {
				strictFeats = append(strictFeats, tok)
			}
		}
		sort.Strings(strictFeats)
		sort.Strings(regularFeats)

		usable := false
		var chosen []string
		reason := ""
		switch {
		case starts >= startupMinStarts && len(regularFeats) >= startupMinFeat:
			usable = true
			chosen = regularFeats
			reason = fmt.Sprintf("满足常规门槛(%.1f 次启动，%d 个特征域名)", starts, len(regularFeats))
		case fgVerifiedApp[id] && starts >= distillStartupMinStartsFG && len(strictFeats) >= 3:
			usable = true
			chosen = strictFeats
			reason = fmt.Sprintf("前台真值切换佐证 + %d 个 100%% 独占业务域名(仅 %.0f 次冷启动即安全生效)", len(strictFeats), starts)
		case starts >= distillStartupMinStartsFast && len(strictFeats) >= 2:
			usable = true
			chosen = strictFeats
			reason = fmt.Sprintf("快速蒸馏通过(%.0f 次冷启动 + %d 个 100%% 独占非 SDK 域名)", starts, len(strictFeats))
		default:
			chosen = strictFeats
			reason = fmt.Sprintf("待补充冷启动(当前 %.1f 次启动、%d 个独占业务域名；建议杀后台重开 1~2 次)", starts, len(strictFeats))
		}
		if usable {
			usableCount++
		}
		nm := a.Name
		if nm == "" {
			nm = id
		}
		out = append(out, DistillStartupItem{
			AppID:        id,
			AppName:      nm,
			Starts:       math.Round(starts*10) / 10,
			FGVerified:   fgVerifiedApp[id],
			FeatTokens:   chosen,
			Usable:       usable,
			StatusReason: reason,
		})
	}

	if b, err := json.Marshal(sfp.fileLocked(now)); err == nil {
		_ = discoverWriteAtomic(startupPath(sfp.hncDir), b)
	}
	sfp.mu.Unlock()

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Usable != out[j].Usable {
			return out[i].Usable
		}
		return out[i].Starts > out[j].Starts
	})
	_ = prevCur
	return out, usableCount, nextCur
}

func buildDistillHints(rep DistillReport) []string {
	var hints []string
	if rep.SamplesScanned == 0 {
		hints = append(hints, "未读到本机真值样本(run/label_samples.*.jsonl)，请先开启「追踪本机应用流量」并打开目标 App 浏览数秒。")
		return hints
	}
	if !rep.ContrastReadyTCP {
		hints = append(hints, fmt.Sprintf(
			"当前仅采集到 %d 个已映射应用；建议顺手打开系统浏览器 + 2 个其它常用 App 产生少量连接后再点一次「立即蒸馏」，可让系统 WebView/OkHttp 通用栈自动显形并解锁纯 TCP 专属栈。",
			rep.DistinctAppsSeen,
		))
	}
	if len(rep.UnmappedPkgs) > 0 {
		maxShow := len(rep.UnmappedPkgs)
		if maxShow > 5 {
			maxShow = 5
		}
		hints = append(hints, fmt.Sprintf(
			"发现 %d 个未在 data/pkg_app_map.json 映射的包名(%s)，补充映射后即可参与专属指纹与启动序列蒸馏。",
			len(rep.UnmappedPkgs), strings.Join(rep.UnmappedPkgs[:maxShow], ", "),
		))
	}
	if rep.GenericBlocked > 0 {
		hints = append(hints, fmt.Sprintf(
			"已自动识别并拦截 %d 条通用 WebView / 浏览器 / 共享 OkHttp·Cronet 指纹，防止其误归属到单一 App。",
			rep.GenericBlocked,
		))
	}
	return hints
}
