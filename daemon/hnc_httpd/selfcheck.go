// selfcheck.go — v5.20 自检报告(多机型兼容性诊断)
//
// GET  /api/selfcheck               → 最近一次自检结果(内存缓存, 重启后读 run/selfcheck.json)
// POST /api/action selfcheck_run    → 立即重跑(≤20s, 各分区并发, 每条命令带超时)
// POST /api/action selfcheck_export → 写 exports/hnc-selfcheck-<ts>.txt + .json(默认脱敏 MAC/IP)
//
// 设计:
//   - 只读: 所有探测都不改系统状态。唯一例外是 capability_probe.sh(用一次性 dummy/ifb
//     口实测 tc 能力并自清理) —— 只在 capabilities.json 缺失或显式 reprobe=1 时跑,
//     平时直接复用它的结果, 不重复探测。
//   - 命令执行/读文件全部走 scEnv 注入(测试用假 runner + 假文件系统喂 ColorOS/高通 与
//     联发科两套真实输出)。
//   - 分区 = goroutine; 总预算 selfcheckBudget, 超时未完成的分区给一条「探测超时」,
//     已完成的照常返回。每条外部命令 selfcheckCmdTimeout 超时 + hardenCmd。
//
// 本文件: 数据结构 + 运行框架 + 各分区探测。HTTP/导出/缓存见 selfcheck_api.go。

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	scOK   = "ok"
	scWarn = "warn"
	scFail = "fail"
	scInfo = "info"

	selfcheckSchema     = 1
	selfcheckBudget     = 18 * time.Second
	selfcheckCmdTimeout = 4 * time.Second
	selfcheckCapTimeout = 12 * time.Second // capability_probe.sh(建/删 dummy 口)
	userHZ              = 100              // Android/arm64 USER_HZ 恒为 100
)

type scItem struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warn | fail | info
	Value  string `json:"value"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

type scSection struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Items     []scItem `json:"items"`
	ElapsedMs int64    `json:"elapsed_ms"`
}

type scSummary struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Info int `json:"info"`
}

type scReport struct {
	Schema       int         `json:"schema"`
	GeneratedAt  int64       `json:"generated_at"`
	GeneratedISO string      `json:"generated_at_iso"`
	Version      string      `json:"version"`
	DurationMs   int64       `json:"duration_ms"`
	Redacted     bool        `json:"redacted"`
	Sections     []scSection `json:"sections"`
	Summary      scSummary   `json:"summary"`
}

// scEnv 外部世界的全部入口(测试注入假实现)。
type scEnv struct {
	HNCDir       string
	Version      string
	SelfPID      int
	LoopbackPort int
	CmdTimeout   time.Duration
	Budget       time.Duration
	// Run 跑一条命令, 返回 stdout; 非 0 退出 / 找不到命令 / 超时 → err != nil
	Run      func(ctx context.Context, name string, args ...string) (string, error)
	ReadFile func(path string) ([]byte, error)
	ReadDir  func(path string) ([]string, error)
	Exists   func(path string) bool
	Getenv   func(key string) string
	Now      func() time.Time
	Sleep    func(ctx context.Context, d time.Duration)
	// CtEvents conntrack DESTROY 事件订阅状态(ct_events.go 的进程内状态)
	CtEvents func() (active bool, lastErr string)
}

type scOptions struct {
	Reprobe bool // 先重跑 capability_probe.sh
}

// ─── 运行上下文(分区间共享的惰性缓存) ─────────────────────────────

type scCtx struct {
	env  *scEnv
	ctx  context.Context
	opts scOptions

	propsOnce sync.Once
	props     map[string]string

	kcfgOnce sync.Once
	kcfg     map[string]string // nil = /proc/config.gz 不可读

	modsOnce sync.Once
	mods     map[string]bool

	capOnce sync.Once
	caps    map[string]interface{}
	capNote string
	// v5.20.1: capabilities.json 存在但解析失败
	capCorrupt bool
}

func (c *scCtx) run(name string, args ...string) (string, bool) {
	to := c.env.CmdTimeout
	if to <= 0 {
		to = selfcheckCmdTimeout
	}
	cctx, cancel := context.WithTimeout(c.ctx, to)
	defer cancel()
	out, err := c.env.Run(cctx, name, args...)
	return out, err == nil
}

func (c *scCtx) read(path string) (string, bool) {
	b, err := c.env.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func (c *scCtx) readTrim(path string) string {
	s, _ := c.read(path)
	return strings.TrimSpace(s)
}

func (c *scCtx) hnc(parts ...string) string {
	return filepath.Join(append([]string{c.env.HNCDir}, parts...)...)
}

func (c *scCtx) readJSON(path string) map[string]interface{} {
	b, err := c.env.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

var scPropLineRE = regexp.MustCompile(`^\[([^\]]+)\]:\s*\[(.*)\]\s*$`)

func scParseGetprop(out string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		if mm := scPropLineRE.FindStringSubmatch(strings.TrimSpace(ln)); mm != nil {
			m[mm[1]] = strings.TrimSpace(mm[2])
		}
	}
	return m
}

// prop 整表 getprop 一次, 各分区共享
func (c *scCtx) prop(key string) string {
	c.propsOnce.Do(func() {
		out, _ := c.run("getprop")
		c.props = scParseGetprop(out)
	})
	return c.props[key]
}

func (c *scCtx) allProps() map[string]string {
	c.prop("")
	return c.props
}

func (c *scCtx) propFirst(keys ...string) string {
	for _, k := range keys {
		if v := c.prop(k); v != "" {
			return v
		}
	}
	return ""
}

// scParseKconfig /proc/config.gz 解压后的文本 → NAME(去 CONFIG_) → y/m/n
func scParseKconfig(text string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "CONFIG_"):
			if i := strings.IndexByte(ln, '='); i > 0 {
				m[ln[7:i]] = strings.Trim(ln[i+1:], "\"")
			}
		case strings.HasPrefix(ln, "# CONFIG_") && strings.HasSuffix(ln, " is not set"):
			m[strings.TrimSuffix(ln[9:], " is not set")] = "n"
		}
	}
	return m
}

func (c *scCtx) kconfig() map[string]string {
	c.kcfgOnce.Do(func() {
		b, err := c.env.ReadFile("/proc/config.gz")
		if err != nil || len(b) == 0 {
			return
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return
		}
		txt, err := io.ReadAll(io.LimitReader(zr, 8<<20))
		if err != nil && len(txt) == 0 {
			return
		}
		c.kcfg = scParseKconfig(string(txt))
	})
	return c.kcfg
}

func (c *scCtx) modules() map[string]bool {
	c.modsOnce.Do(func() {
		c.mods = map[string]bool{}
		s, _ := c.read("/proc/modules")
		for _, ln := range strings.Split(s, "\n") {
			if f := strings.Fields(ln); len(f) > 0 {
				c.mods[f[0]] = true
			}
		}
	})
	return c.mods
}

func (c *scCtx) moduleMatching(re *regexp.Regexp) []string {
	var out []string
	for m := range c.modules() {
		if re.MatchString(m) {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// capabilities 复用 capability_probe.sh 的结果; 缺失或 reprobe 时先跑一次(自清理)。
func (c *scCtx) capabilities() map[string]interface{} {
	c.capOnce.Do(func() {
		path := c.hnc("run", "capabilities.json")
		m := c.readJSON(path)
		if m == nil && c.env.Exists(path) {
			// v5.20.1: 文件在但不是合法 JSON(真机: selinux_avc_denied_recent 写成 "0\n0")
			c.capCorrupt = true
		}
		if m == nil || c.opts.Reprobe {
			script := c.hnc("bin", "capability_probe.sh")
			if c.env.Exists(script) {
				cctx, cancel := context.WithTimeout(c.ctx, selfcheckCapTimeout)
				_, err := c.env.Run(cctx, "sh", script)
				cancel()
				if err != nil {
					c.capNote = "capability_probe.sh 执行失败: " + scShort(err.Error(), 120)
				} else {
					c.capNote = "本次自检已重新探测"
				}
				if m2 := c.readJSON(path); m2 != nil {
					m = m2
				}
			} else if m == nil {
				c.capNote = "capability_probe.sh 不存在"
			}
		}
		c.caps = m
	})
	return c.caps
}

// capBool: (值, 是否有明确 true/false)
func (c *scCtx) capBool(key string) (bool, bool) {
	m := c.capabilities()
	if m == nil {
		return false, false
	}
	v, ok := m[key].(bool)
	return v, ok
}

func (c *scCtx) capStr(key string) string {
	m := c.capabilities()
	if m == nil {
		return ""
	}
	return asString(m[key])
}

// hotspotIface 与 server.currentHotspotIface 同优先级: hnc_state ACTIVE: > iface.cache > rules.json
func (c *scCtx) hotspotIface() string {
	if s := c.readTrim(c.hnc("run", "hnc_state")); strings.HasPrefix(s, "ACTIVE:") {
		if v := strings.TrimSpace(strings.TrimPrefix(s, "ACTIVE:")); v != "" {
			return v
		}
	}
	if s := c.readTrim(c.hnc("run", "iface.cache")); s != "" {
		return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	}
	if m := c.readJSON(c.hnc("data", "rules.json")); m != nil {
		return strings.TrimSpace(asString(m["hotspot_iface"]))
	}
	return ""
}

// ─── 运行框架 ────────────────────────────────────────────────────

type scSectionDef struct {
	ID, Title string
	Fn        func(c *scCtx) []scItem
}

func selfcheckSections() []scSectionDef {
	return []scSectionDef{
		{"system", "设备与系统", scSectionSystem},
		{"shaping", "限速能力", scSectionShaping},
		{"firewall", "防火墙", scSectionFirewall},
		{"offload", "硬件加速", scSectionOffload},
		{"network", "热点与网络", scSectionNetwork},
		{"ipv6", "IPv6 覆盖", scSectionIPv6},
		{"time", "时间", scSectionTime},
		{"process", "进程与资源", scSectionProcess},
		{"ident", "识别", scSectionIdent},
	}
}

func runSelfcheck(env *scEnv, opts scOptions) *scReport {
	return runSelfcheckDefs(env, opts, selfcheckSections())
}

func runSelfcheckDefs(env *scEnv, opts scOptions, defs []scSectionDef) *scReport {
	start := env.Now()
	budget := env.Budget
	if budget <= 0 {
		budget = selfcheckBudget
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	c := &scCtx{env: env, ctx: ctx, opts: opts}

	type res struct {
		i   int
		sec scSection
	}
	ch := make(chan res, len(defs))
	for i, d := range defs {
		go func(i int, d scSectionDef) {
			t0 := time.Now()
			var items []scItem
			func() {
				defer func() {
					if r := recover(); r != nil {
						items = append(items, scItem{ID: d.ID + "_panic", Label: "探测异常", Status: scWarn,
							Value: "探测代码异常退出", Detail: scShort(fmt.Sprint(r), 200)})
					}
				}()
				items = d.Fn(c)
			}()
			ch <- res{i, scSection{ID: d.ID, Title: d.Title, Items: items, ElapsedMs: time.Since(t0).Milliseconds()}}
		}(i, d)
	}
	secs := make([]scSection, len(defs))
	got := make([]bool, len(defs))
	for n := 0; n < len(defs); {
		select {
		case r := <-ch:
			secs[r.i], got[r.i] = r.sec, true
			n++
		case <-ctx.Done():
			n = len(defs)
		}
	}
	for i, d := range defs {
		if !got[i] {
			secs[i] = scSection{ID: d.ID, Title: d.Title, ElapsedMs: budget.Milliseconds(), Items: []scItem{{
				ID: d.ID + "_timeout", Label: "探测超时", Status: scWarn,
				Value:  fmt.Sprintf("超过 %d 秒未完成", int(budget.Seconds())),
				Detail: "该分区的系统命令响应过慢(ROM 限制或系统繁忙), 结果不完整",
				Fix:    "稍后重新自检; 反复超时请导出报告反馈"}}}
		}
		if secs[i].Items == nil {
			secs[i].Items = []scItem{}
		}
	}
	now := env.Now()
	r := &scReport{
		Schema:       selfcheckSchema,
		GeneratedAt:  now.Unix(),
		GeneratedISO: now.Format(time.RFC3339),
		Version:      env.Version,
		DurationMs:   now.Sub(start).Milliseconds(),
		Sections:     secs,
	}
	r.Summary = scSummarize(secs)
	return r
}

func scSummarize(secs []scSection) scSummary {
	var s scSummary
	for _, sec := range secs {
		for _, it := range sec.Items {
			switch it.Status {
			case scOK:
				s.OK++
			case scWarn:
				s.Warn++
			case scFail:
				s.Fail++
			default:
				s.Info++
			}
		}
	}
	return s
}

// ─── 小工具 ──────────────────────────────────────────────────────

func scShort(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func scBytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", b/(1<<10))
	}
	return fmt.Sprintf("%.0f B", b)
}

func scDur(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	d, h, m := sec/86400, (sec%86400)/3600, (sec%3600)/60
	switch {
	case d > 0:
		return fmt.Sprintf("%d 天 %d 小时", d, h)
	case h > 0:
		return fmt.Sprintf("%d 小时 %d 分", h, m)
	case m > 0:
		return fmt.Sprintf("%d 分钟", m)
	}
	return fmt.Sprintf("%d 秒", sec)
}

func scYesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// scNetIfaces /sys/class/net 下的接口名
func (c *scCtx) netIfaces() []string {
	names, _ := c.env.ReadDir("/sys/class/net")
	sort.Strings(names)
	return names
}

func (c *scCtx) operstate(iface string) string {
	return c.readTrim("/sys/class/net/" + iface + "/operstate")
}

// ═══ 设备与系统 ═══════════════════════════════════════════════════

type scROM struct{ Name, Ver string }

// scDetectROM 按厂商私有属性识别 ROM(纯函数, 测试直接喂 props)
func scDetectROM(p map[string]string) scROM {
	g := func(k ...string) string {
		for _, x := range k {
			if v := strings.TrimSpace(p[x]); v != "" {
				return v
			}
		}
		return ""
	}
	if v := g("ro.build.version.oplusrom", "ro.build.version.opporom", "ro.build.version.oplusrom.display"); v != "" {
		name := "ColorOS"
		if b := strings.ToLower(p["ro.product.brand"]); b == "oneplus" {
			name = "ColorOS/OxygenOS"
		}
		return scROM{name, v}
	}
	if v := g("ro.mi.os.version.name", "ro.mi.os.version.incremental"); v != "" {
		return scROM{"HyperOS", v}
	}
	if v := g("ro.miui.ui.version.name"); v != "" {
		return scROM{"MIUI", v}
	}
	if v := g("ro.build.version.oneui"); v != "" {
		// 60101 → 6.1.1
		if n, err := strconv.Atoi(v); err == nil && n > 10000 {
			v = fmt.Sprintf("%d.%d", n/10000, (n%10000)/100)
			if n%100 != 0 {
				v += "." + strconv.Itoa(n%100)
			}
		}
		return scROM{"One UI", v}
	}
	if v := g("ro.vivo.os.name"); v != "" {
		return scROM{v, g("ro.vivo.os.version", "ro.vivo.product.version")}
	}
	if v := g("ro.vivo.os.version"); v != "" {
		return scROM{"OriginOS/FuntouchOS", v}
	}
	if v := g("ro.build.version.magic"); v != "" {
		return scROM{"MagicOS", v}
	}
	if v := g("ro.build.version.emui"); v != "" {
		return scROM{"EMUI/HarmonyOS", v}
	}
	if v := g("ro.flyme.version.id", "ro.build.flyme.version"); v != "" {
		return scROM{"Flyme", v}
	}
	if v := g("ro.rom.version", "ro.os.version.release"); v != "" && strings.EqualFold(p["ro.product.brand"], "nothing") {
		return scROM{"Nothing OS", v}
	}
	if strings.EqualFold(p["ro.product.brand"], "google") {
		return scROM{"Pixel(原生)", ""}
	}
	return scROM{"AOSP/其他", ""}
}

// scSoCVendor SoC 厂商: qualcomm | mediatek | samsung | unisoc | google | unknown
func scSoCVendor(p map[string]string) string {
	man := strings.ToLower(p["ro.soc.manufacturer"])
	switch {
	case strings.Contains(man, "qti") || strings.Contains(man, "qualcomm"):
		return "qualcomm"
	case strings.Contains(man, "mediatek") || man == "mtk":
		return "mediatek"
	case strings.Contains(man, "samsung"):
		return "samsung"
	case strings.Contains(man, "unisoc") || strings.Contains(man, "spreadtrum"):
		return "unisoc"
	case strings.Contains(man, "google"):
		return "google"
	}
	s := strings.ToLower(p["ro.soc.model"] + " " + p["ro.board.platform"] + " " + p["ro.hardware"] + " " + p["ro.hardware.chipname"])
	switch {
	case regexp.MustCompile(`\bmt\d{4}|mediatek|\bmtk`).MatchString(s):
		return "mediatek"
	case regexp.MustCompile(`\bsm\d{4}|\bsdm\d|\bmsm\d|\bqcom|\bkona|\blahaina|\btaro|\bkalama|\bpineapple|\bsun\b|\bcanoe|\bparrot|\bcrow|\bholi|\bblair|\bbengal|\bcliffs`).MatchString(s):
		return "qualcomm"
	case regexp.MustCompile(`exynos|\bs5e\d|\berd\d|universal\d`).MatchString(s):
		return "samsung"
	case regexp.MustCompile(`\bums\d|\bsp\d{4}|unisoc|sprd|\bud\d{3}|\bt\d{3}\b`).MatchString(s):
		return "unisoc"
	case regexp.MustCompile(`\bgs\d{3}|\bzuma|\bzumapro|\blaguna|tensor`).MatchString(s):
		return "google"
	}
	return "unknown"
}

var scSoCName = map[string]string{
	"qualcomm": "高通 Qualcomm", "mediatek": "联发科 MediaTek", "samsung": "三星 Exynos",
	"unisoc": "紫光展锐 Unisoc", "google": "Google Tensor", "unknown": "未知",
}

var scGKIRE = regexp.MustCompile(`-(android\d+)-(\d+)`)

// scKernelInfo "6.6.56-android15-8-gabc" → ("android15-6.6", true)
func scKernelInfo(rel string) (string, bool) {
	m := scGKIRE.FindStringSubmatch(rel)
	if m == nil {
		return "", false
	}
	mm := regexp.MustCompile(`^(\d+\.\d+)`).FindString(rel)
	return m[1] + "-" + mm, true
}

type scRoot struct {
	Impls    []string // KernelSU / SukiSU / KernelSU-Next / Magisk / APatch
	Label    string   // 单一实现时的显示名(可能是 "KernelSU 系(可能为 SukiSU)")
	Evidence []string // KernelSU 分支识别证据
	Version  string
	SuSFS    bool
	Meta     []string
	Detail   string
}

var scVerMajorRE = regexp.MustCompile(`(\d+)\.\d+`)

// ksuVariant v5.20.1: KernelSU 分支识别(与 bin/hnc_compat.sh hnc_root_detect 同一套证据):
//
//	强: ksud -V 含 "suki" / 管理器数据目录 com.sukisu.ultra
//	中: ksud --help 有 kpm 子命令 / /data/adb/kpm(KPM 在 KSU 系里是 SukiSU 独有)
//	弱: SuSFS、ksud 主版本 ≥3(官方 KernelSU / KSU-Next 仍是 1.x–2.x)
//
// 只有弱证据 → ("KernelSU", "KernelSU 系(可能为 SukiSU)")。真机 RMX5010 的 ksud -V 是
// "KernelSU ksud 4.2.0-rc1 (uapi: 2)", 不含 suki。
func (c *scCtx) ksuVariant(ver string) (name, label string, ev []string) {
	ex := c.env.Exists
	strong, medium, weak := false, false, false
	lv := strings.ToLower(ver)
	if strings.Contains(lv, "suki") {
		strong, ev = true, append(ev, "ksud_version_sukisu")
	}
	for _, d := range []string{"/data/data/com.sukisu.ultra", "/data/user_de/0/com.sukisu.ultra"} {
		if ex(d) {
			strong, ev = true, append(ev, "manager_com.sukisu.ultra")
			break
		}
	}
	for _, b := range []string{"/data/adb/ksud", "/data/adb/ksu/bin/ksud"} {
		if !ex(b) {
			continue
		}
		if out, ok := c.run(b, "--help"); ok {
			for _, ln := range strings.Split(out, "\n") {
				f := strings.Fields(ln)
				if len(f) > 0 && strings.EqualFold(f[0], "kpm") && strings.HasPrefix(ln, " ") {
					medium, ev = true, append(ev, "ksud_kpm_cmd")
					break
				}
			}
		}
		break
	}
	if ex("/data/adb/kpm") {
		medium, ev = true, append(ev, "adb_kpm_dir")
	}
	if ex("/data/adb/ksu/bin/ksu_susfs") || ex("/data/adb/modules/susfs4ksu") {
		weak, ev = true, append(ev, "susfs")
	}
	if m := scVerMajorRE.FindStringSubmatch(ver); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n >= 3 {
			weak, ev = true, append(ev, "ksud_major_ge3")
		}
	}
	switch {
	case strong || medium:
		return "SukiSU", "SukiSU", ev
	case ex("/data/data/com.rifsxd.ksunext") || strings.Contains(lv, "next"):
		return "KernelSU-Next", "KernelSU-Next", ev
	case weak:
		return "KernelSU", "KernelSU 系(可能为 SukiSU)", ev
	}
	return "KernelSU", "KernelSU", ev
}

func (c *scCtx) detectRoot() scRoot {
	var r scRoot
	var vers []string
	ex := c.env.Exists
	if ex("/data/adb/ksud") || ex("/data/adb/ksu") {
		name := "KernelSU"
		v := ""
		for _, b := range []string{"/data/adb/ksud", "/data/adb/ksu/bin/ksud"} {
			if ex(b) {
				if out, ok := c.run(b, "-V"); ok && strings.TrimSpace(out) != "" {
					v = scShort(out, 60)
					break
				}
			}
		}
		if v == "" {
			v = c.env.Getenv("KSU_VER")
		}
		name, r.Label, r.Evidence = c.ksuVariant(v)
		r.Impls = append(r.Impls, name)
		if v != "" {
			vers = append(vers, name+" "+v)
		}
	}
	if ex("/data/adb/magisk") || ex("/data/adb/magisk.db") {
		r.Impls = append(r.Impls, "Magisk")
		v := ""
		if out, ok := c.run("magisk", "-v"); ok {
			v = scShort(out, 40)
		}
		if v == "" {
			v = c.env.Getenv("MAGISK_VER")
		}
		if v != "" {
			vers = append(vers, "Magisk "+v)
		}
	}
	if ex("/data/adb/ap") || ex("/data/adb/apd") {
		r.Impls = append(r.Impls, "APatch")
		v := ""
		if ex("/data/adb/apd") {
			if out, ok := c.run("/data/adb/apd", "-V"); ok {
				v = scShort(out, 40)
			}
		}
		if v == "" {
			v = c.env.Getenv("APATCH_VER")
		}
		if v != "" {
			vers = append(vers, "APatch "+v)
		}
	}
	r.SuSFS = ex("/data/adb/ksu/bin/ksu_susfs") || ex("/data/adb/modules/susfs4ksu")
	if mods, err := c.env.ReadDir("/data/adb/modules"); err == nil {
		for _, m := range mods {
			l := strings.ToLower(m)
			if strings.Contains(l, "magic_mount") || strings.Contains(l, "meta") || strings.Contains(l, "overlayfs") || strings.Contains(l, "mountify") {
				r.Meta = append(r.Meta, m)
			}
		}
		sort.Strings(r.Meta)
	}
	r.Version = strings.Join(vers, "; ")
	return r
}

func scSectionSystem(c *scCtx) []scItem {
	var items []scItem
	brand, model := c.prop("ro.product.brand"), c.prop("ro.product.model")
	market := c.propFirst("ro.vendor.oplus.market.name", "ro.product.marketname", "ro.product.vendor.marketname", "ro.config.marketing_name")
	if model == "" {
		items = append(items, scItem{ID: "device_model", Label: "机型", Status: scWarn, Value: "未知",
			Detail: "getprop 无输出(命令不可用或被 SELinux 拦截)", Fix: "确认 /system/bin/getprop 可用"})
	} else {
		v := strings.TrimSpace(brand + " " + model)
		if market != "" && market != model {
			v += "(" + market + ")"
		}
		items = append(items, scItem{ID: "device_model", Label: "机型", Status: scInfo, Value: v,
			Detail: "device=" + c.propFirst("ro.product.device", "ro.product.name") + " manufacturer=" + c.prop("ro.product.manufacturer")})
	}

	rel, sdk := c.prop("ro.build.version.release"), c.prop("ro.build.version.sdk")
	it := scItem{ID: "android_version", Label: "Android 版本", Status: scInfo, Value: "Android " + rel + "(SDK " + sdk + ")"}
	if n, err := strconv.Atoi(sdk); err == nil && n < 29 {
		it.Status = scWarn
		it.Detail = "低于 Android 10 的系统未经测试, 部分功能(tether BPF / cmd wifi)不可用"
	}
	items = append(items, it)

	rom := scDetectROM(c.allProps())
	items = append(items, scItem{ID: "rom", Label: "系统 ROM", Status: scInfo,
		Value:  strings.TrimSpace(rom.Name + " " + rom.Ver),
		Detail: "build=" + c.prop("ro.build.display.id") + " 安全补丁=" + c.prop("ro.build.version.security_patch")})

	vendor := scSoCVendor(c.allProps())
	socV := scSoCName[vendor]
	if m := c.propFirst("ro.soc.model", "ro.hardware.chipname"); m != "" {
		socV += " · " + m
	}
	if pl := c.prop("ro.board.platform"); pl != "" {
		socV += "(" + pl + ")"
	}
	items = append(items, scItem{ID: "soc", Label: "SoC 平台", Status: scInfo, Value: socV,
		Detail: "vendor=" + vendor + " hardware=" + c.prop("ro.hardware")})

	krel := c.readTrim("/proc/sys/kernel/osrelease")
	if krel == "" {
		if out, ok := c.run("uname", "-r"); ok {
			krel = strings.TrimSpace(out)
		}
	}
	kit := scItem{ID: "kernel", Label: "内核", Status: scOK, Value: krel}
	if gki, ok := scKernelInfo(krel); ok {
		kit.Value += "(GKI " + gki + ")"
	} else if krel != "" {
		kit.Status = scInfo
		kit.Detail = "非 GKI 内核: tether BPF offload、tc 模块由厂商配置决定, 以下「限速能力」以实测为准"
	} else {
		kit.Status = scWarn
		kit.Value = "未知"
	}
	if mm := regexp.MustCompile(`^(\d+)\.(\d+)`).FindStringSubmatch(krel); mm != nil {
		maj, _ := strconv.Atoi(mm[1])
		min, _ := strconv.Atoi(mm[2])
		if maj < 4 || (maj == 4 && min < 14) {
			kit.Status = scWarn
			kit.Detail = "内核低于 4.14, ifb/clsact/conntrack 事件等能力可能缺失"
		}
	}
	items = append(items, kit)

	root := c.detectRoot()
	rit := scItem{ID: "root", Label: "Root 实现", Status: scOK}
	switch len(root.Impls) {
	case 0:
		rit.Status, rit.Value = scWarn, "未识别"
		rit.Detail = "未找到 /data/adb/ksu、/data/adb/magisk、/data/adb/ap"
	case 1:
		rit.Value = root.Impls[0]
		if root.Label != "" {
			rit.Value = root.Label
		}
	default:
		rit.Status = scWarn
		rit.Value = strings.Join(root.Impls, " + ")
		rit.Detail = "检测到多个 root 实现的目录, 可能是残留, 注意不要同时启用"
	}
	var dt []string
	if root.Version != "" {
		dt = append(dt, "版本: "+root.Version)
	}
	if root.SuSFS {
		dt = append(dt, "SuSFS: 已安装")
	}
	if len(root.Evidence) > 0 {
		dt = append(dt, "分支识别依据: "+strings.Join(root.Evidence, ","))
	}
	if len(root.Meta) > 0 {
		dt = append(dt, "挂载元模块: "+strings.Join(root.Meta, ","))
	}
	if len(dt) > 0 {
		if rit.Detail != "" {
			rit.Detail += "; "
		}
		rit.Detail += strings.Join(dt, "; ")
	}
	items = append(items, rit)

	se := c.readTrim("/sys/fs/selinux/enforce")
	seV := ""
	switch se {
	case "1":
		seV = "Enforcing(强制)"
	case "0":
		seV = "Permissive(宽容)"
	default:
		if out, ok := c.run("getenforce"); ok {
			seV = strings.TrimSpace(out)
		}
	}
	sit := scItem{ID: "selinux", Label: "SELinux", Status: scInfo, Value: seV}
	if seV == "" {
		sit.Value = "未知"
	}
	if m := c.capabilities(); m != nil {
		if n, ok := toInt64(m["selinux_avc_denied_recent"]); ok && n > 0 {
			sit.Status = scWarn
			sit.Detail = fmt.Sprintf("dmesg 中有 %d 条与 HNC 相关的 avc denied", n)
			sit.Fix = "导出诊断包查看 dmesg; 必要时在 root 管理器里给模块放行 SELinux 规则"
		}
		if d := asString(m["su_domain"]); d != "" && d != "unknown" {
			if sit.Detail != "" {
				sit.Detail += "; "
			}
			sit.Detail += "root 域: " + d
		}
	}
	items = append(items, sit)

	moddir := c.readTrim(c.hnc("run", "service.path"))
	if moddir == "" && c.env.Exists("/data/adb/modules/hotspot_network_control") {
		moddir = "/data/adb/modules/hotspot_network_control"
	}
	mit := scItem{ID: "module_path", Label: "模块路径", Status: scOK, Value: moddir, Detail: "数据目录: " + c.env.HNCDir}
	if moddir == "" {
		mit.Status, mit.Value = scWarn, "未知"
		mit.Fix = "重启一次让 service.sh 记录模块路径"
	} else if !c.env.Exists(moddir) {
		mit.Status = scWarn
		mit.Detail += "; 记录的模块目录已不存在(模块被移动/卸载?)"
	}
	if !c.env.Exists(c.env.HNCDir) {
		mit.Status = scFail
		mit.Detail = "数据目录不存在: " + c.env.HNCDir
	}
	items = append(items, mit)

	wit := scItem{ID: "webui_entry", Label: "WebUI 入口"}
	hasKSU, hasMagisk := false, false
	for _, im := range root.Impls {
		switch im {
		case "KernelSU", "SukiSU", "KernelSU-Next", "APatch":
			hasKSU = true
		case "Magisk":
			hasMagisk = true
		}
	}
	port := c.env.LoopbackPort
	if port <= 0 {
		port = 8444
	}
	switch {
	case hasKSU:
		wit.Status, wit.Value = scOK, "root 管理器内置 WebUI 可用"
	case hasMagisk:
		wit.Status, wit.Value = scInfo, "Magisk 无模块 WebUI 入口"
		wit.Fix = fmt.Sprintf("用手机浏览器打开 http://127.0.0.1:%d, 或安装 KsuWebUI 类应用", port)
	default:
		wit.Status, wit.Value = scWarn, "未知"
		wit.Fix = fmt.Sprintf("可用浏览器打开 http://127.0.0.1:%d", port)
	}
	items = append(items, wit)

	if v, ok := c.capBool("kernel_blocks_clone_vm"); ok {
		fit := scItem{ID: "fork_compat", Label: "进程拉起兼容", Status: scOK, Value: "正常"}
		if v {
			fit.Status = scInfo
			fit.Value = "内核拦截 Go fork(CLONE_VM), 已用 C launcher 绕过"
		}
		if l := c.capStr("selected_launcher"); l != "" {
			fit.Detail = "launcher=" + l
		}
		items = append(items, fit)
	}
	return items
}

// ═══ 限速能力 ═════════════════════════════════════════════════════

type scFeature struct {
	ID, Label  string
	CapKeys    []string // capabilities.json 实测键(按序第一个有 bool 的)
	Kcfg       []string // CONFIG_ 名(去前缀), 任一 y/m 即支持
	Mods       []string // /proc/modules 名
	Importance string   // required | recommended | optional
	Why        string   // 不支持时的影响
	Qdisc      string   // run/qdisc_caps.json 里的 qdisc 名(低延迟兜底链实测)
}

var scTCFeatures = []scFeature{
	{"tc_htb", "HTB 分层限速", []string{"tc_htb"}, []string{"NET_SCH_HTB"}, []string{"sch_htb"}, "required", "下行限速核心, 不支持则无法按设备限速", ""},
	{"tc_ifb", "IFB 虚拟口", []string{"tc_ifb_create", "ifb_supported"}, []string{"IFB"}, []string{"ifb"}, "recommended", "上行精确限速需要 IFB, 缺失时退化为 police 丢包限速", ""},
	{"tc_mirred", "mirred 重定向", []string{"tc_mirred"}, []string{"NET_ACT_MIRRED"}, []string{"act_mirred"}, "recommended", "上行流量无法重定向到 IFB", ""},
	{"tc_police", "police 限速动作", []string{"tc_police_supported"}, []string{"NET_ACT_POLICE"}, []string{"act_police"}, "optional", "IFB 不可用时的上行兜底也不可用", ""},
	{"tc_netem", "netem 延迟模拟", []string{"tc_netem"}, []string{"NET_SCH_NETEM"}, []string{"sch_netem"}, "recommended", "设备延迟/丢包模拟不可用", ""},
	{"tc_sfq", "SFQ 公平队列", nil, []string{"NET_SCH_SFQ"}, []string{"sch_sfq"}, "optional", "低延迟模式少一个兜底队列", "sfq"},
	{"tc_fq", "FQ 队列", nil, []string{"NET_SCH_FQ"}, []string{"sch_fq"}, "optional", "", "fq"},
	{"tc_fq_codel", "fq_codel", []string{"tc_fq_codel"}, []string{"NET_SCH_FQ_CODEL"}, []string{"sch_fq_codel"}, "optional", "低延迟模式退回 sfq", "fq_codel"},
	{"tc_cake", "CAKE", []string{"tc_cake"}, []string{"NET_SCH_CAKE"}, []string{"sch_cake"}, "optional", "低延迟模式退回 fq_codel/sfq", "cake"},
	{"tc_clsact", "clsact/ingress", []string{"tc_clsact_supported", "tc_ingress_supported"}, []string{"NET_SCH_INGRESS"}, []string{"sch_ingress"}, "recommended", "上行 ingress 截流与 offload 兜底打标不可用", ""},
	{"tc_bpf", "BPF 分类器", nil, []string{"NET_CLS_BPF", "NET_ACT_BPF"}, []string{"cls_bpf", "act_bpf"}, "optional", "clsact BPF 打标不可用(不影响主限速)", ""},
	{"tc_u32", "u32 分类器", []string{"tc_u32_supported"}, []string{"NET_CLS_U32"}, []string{"cls_u32"}, "required", "无法按 IP 把流量分到设备的限速类", ""},
	{"tc_fw", "fw 标记分类", nil, []string{"NET_CLS_FW"}, []string{"cls_fw"}, "optional", "IPv6 的 iptables mark 兜底分类不可用", ""},
}

// scResolveFeature → (state: yes|no|maybe|unknown, source)
func scResolveFeature(f scFeature, caps map[string]interface{}, qd map[string]bool, kcfg map[string]string, mods map[string]bool) (string, string) {
	if f.Qdisc != "" {
		if v, ok := qd[f.Qdisc]; ok {
			if v {
				return "yes", "实测(低延迟兜底链)"
			}
			if len(f.CapKeys) == 0 {
				return "no", "实测失败(低延迟兜底链)"
			}
		}
	}
	for _, k := range f.CapKeys {
		if caps == nil {
			break
		}
		if v, ok := caps[k].(bool); ok {
			if v {
				return "yes", "实测"
			}
			// 实测失败但内核配置明确编进了(=y), 仍以实测为准(可能是 iproute2 太旧)
			return "no", "实测失败"
		}
	}
	for _, m := range f.Mods {
		if mods[m] {
			return "yes", "模块已加载"
		}
	}
	if kcfg != nil {
		state := "no"
		for _, k := range f.Kcfg {
			switch kcfg[k] {
			case "y":
				return "yes", "内核内建(=y)"
			case "m":
				state = "maybe"
			}
		}
		if state == "maybe" {
			return "maybe", "内核模块(=m), 当前未加载"
		}
		return "no", "内核配置未启用"
	}
	return "unknown", "无实测结果且 /proc/config.gz 不可读"
}

// scParseQdiscCaps run/qdisc_caps.json(qdisc_caps.sh) → qdisc 名 → 是否可用, chosen
func scParseQdiscCaps(m map[string]interface{}) (map[string]bool, string) {
	res := map[string]bool{}
	if m == nil {
		return res, ""
	}
	if tried, ok := m["tried"].([]interface{}); ok {
		for _, t := range tried {
			tm, _ := t.(map[string]interface{})
			if n := asString(tm["name"]); n != "" {
				ok, _ := tm["ok"].(bool)
				res[n] = res[n] || ok
			}
		}
	}
	if av, ok := m["available"].([]interface{}); ok {
		for _, a := range av {
			if n := asString(a); n != "" {
				res[n] = true
			}
		}
	}
	return res, asString(m["chosen"])
}

// scQdiscTriedSummary qdisc_caps.json tried[] → "cake(tc_probe 失败, modprobe 失败) · sfq(tc_probe 成功)"
// 按名字分组、保持出现顺序; proc_modules 只是记录是否已加载, 不列。
func scQdiscTriedSummary(m map[string]interface{}) string {
	tried, _ := m["tried"].([]interface{})
	if len(tried) == 0 {
		return ""
	}
	var order []string
	parts := map[string][]string{}
	for _, t := range tried {
		tm, _ := t.(map[string]interface{})
		n := asString(tm["name"])
		if n == "" {
			continue
		}
		meth := asString(tm["method"])
		if meth == "proc_modules" {
			continue
		}
		if meth == "" {
			meth = "?"
		}
		res := "失败"
		if ok, _ := tm["ok"].(bool); ok {
			res = "成功"
		}
		if _, seen := parts[n]; !seen {
			order = append(order, n)
		}
		parts[n] = append(parts[n], meth+" "+res)
	}
	var out []string
	for _, n := range order {
		out = append(out, n+"("+strings.Join(parts[n], ", ")+")")
	}
	return scShort(strings.Join(out, " · "), 400)
}

// scFeatureStatus 支持情况 × 重要性 → 状态(纯函数)
func scFeatureStatus(state, importance string) string {
	switch state {
	case "yes":
		return scOK
	case "no":
		switch importance {
		case "required":
			return scFail
		case "recommended":
			return scWarn
		}
		return scInfo
	}
	return scInfo
}

func scSectionShaping(c *scCtx) []scItem {
	var items []scItem
	caps := c.capabilities()
	cit := scItem{ID: "cap_probe", Label: "能力探测结果", Status: scOK}
	if caps == nil {
		cit.Status, cit.Value = scFail, "缺失"
		cit.Detail = "run/capabilities.json 不存在或损坏; " + c.capNote
		if c.capCorrupt {
			cit.Detail = "run/capabilities.json 存在但不是合法 JSON(旧版探针的计数字段会写坏文件, 升级后自动修复); " + c.capNote
		}
		cit.Fix = "重启 HNC 服务或在自检里勾选「重新探测」"
	} else {
		ts, _ := toInt64(caps["generated_at"])
		age := c.env.Now().Unix() - ts
		cit.Value = scDur(age) + "前"
		if ts <= 0 {
			cit.Value = "时间未知"
		}
		cit.Detail = "probe=" + asString(caps["probe"])
		switch asString(caps["qdisc_probe"]) {
		case "pending":
			cit.Detail += "; 低延迟队列探测进行中(基础能力已写出)"
		case "timeout":
			cit.Detail += "; 低延迟队列探测超时(本次开机不再尝试加载内核模块)"
		}
		if c.capNote != "" {
			cit.Detail += "; " + c.capNote
		}
		if age > 7*86400 {
			cit.Status = scInfo
			cit.Fix = "结果较旧, 系统更新后建议重新探测"
		}
	}
	items = append(items, cit)

	tit := scItem{ID: "tc_binary", Label: "tc 命令", Status: scOK}
	if caps != nil {
		tit.Value = asString(caps["tc_binary"])
		tit.Detail = asString(caps["tc_version"]) + " · 来源 " + asString(caps["tc_binary_source"])
		if ok, _ := caps["tc_binary_ok"].(bool); !ok {
			tit.Status = scFail
			tit.Fix = "系统 tc 不可用, 无法限速; 请反馈机型"
		}
	} else if out, ok := c.run("tc", "-V"); ok {
		tit.Value = "tc"
		tit.Detail = scShort(out, 100)
	} else {
		tit.Status, tit.Value = scFail, "未找到"
		tit.Fix = "系统缺少 tc, 无法限速"
	}
	items = append(items, tit)

	ps := c.readTrim("/proc/net/psched")
	pit := scItem{ID: "psched", Label: "调度时钟", Status: scOK}
	if f := strings.Fields(ps); len(f) == 4 {
		if f[3] == "3b9aca00" {
			pit.Value = "高精度(hrtimer 1GHz)"
		} else {
			pit.Value = "分辨率 0x" + f[3]
			pit.Status = scInfo
		}
		pit.Detail = ps
	} else {
		pit.Status, pit.Value = scWarn, "不可读"
		pit.Detail = "/proc/net/psched 缺失, 内核可能未启用 NET_SCHED"
	}
	items = append(items, pit)

	kc := c.kconfig()
	kit := scItem{ID: "kernel_config", Label: "内核配置", Status: scInfo}
	if kc != nil {
		kit.Value = fmt.Sprintf("可读(/proc/config.gz, %d 项)", len(kc))
	} else {
		kit.Value = "不可读"
		kit.Detail = "只能依据实测与已加载模块判断, 未实测的项目显示为未知"
	}
	items = append(items, kit)

	mods := c.modules()
	qcRaw := c.readJSON(c.hnc("run", "qdisc_caps.json"))
	qd, chosen := scParseQdiscCaps(qcRaw)
	supported := map[string]bool{}
	for _, f := range scTCFeatures {
		state, src := scResolveFeature(f, caps, qd, kc, mods)
		supported[f.ID] = state == "yes"
		st := scFeatureStatus(state, f.Importance)
		val := map[string]string{"yes": "支持", "no": "不支持", "maybe": "可能支持", "unknown": "未知"}[state]
		it := scItem{ID: f.ID, Label: f.Label, Status: st, Value: val, Detail: src}
		if state == "no" && f.Why != "" {
			it.Detail += "; " + f.Why
		}
		if state == "no" && caps != nil {
			for _, k := range f.CapKeys {
				if e := asString(caps[strings.TrimSuffix(strings.TrimSuffix(k, "_supported"), "_create")+"_error"]); e != "" {
					it.Detail += "; 错误: " + scShort(e, 120)
					break
				}
			}
		}
		items = append(items, it)
	}

	sqm := scItem{ID: "low_latency", Label: "低延迟队列", Status: scOK}
	if chosen == "" {
		chosen = c.capStr("qdisc_lowlat_chosen")
	}
	switch {
	case chosen == "cake" || chosen == "fq_codel" || chosen == "fq":
		sqm.Value = chosen
		sqm.Detail = "由低延迟兜底链选定"
	case chosen == "sfq":
		sqm.Value = "sfq(无 cake/fq_codel)"
		sqm.Status = scInfo
	case chosen == "pfifo":
		sqm.Status, sqm.Value = scWarn, "仅 pfifo"
		sqm.Detail = "cake / fq_codel / fq / sfq 均不可用, 设备「低延迟」开关效果有限"
	case supported["tc_cake"]:
		sqm.Value = "cake"
	case supported["tc_fq_codel"]:
		sqm.Value = "fq_codel"
	case supported["tc_sfq"]:
		sqm.Value = "sfq(无 cake/fq_codel)"
		sqm.Status = scInfo
	default:
		sqm.Status, sqm.Value = scWarn, "不可用"
		sqm.Detail = "cake / fq_codel / sfq 均未检测到, 设备「低延迟」开关不起作用"
	}
	if tried := scQdiscTriedSummary(qcRaw); tried != "" {
		if sqm.Detail != "" {
			sqm.Detail += "; "
		}
		sqm.Detail += "尝试记录: " + tried
	}
	items = append(items, sqm)

	if caps != nil {
		up := asString(caps["uplink_mode"])
		uit := scItem{ID: "uplink_mode", Label: "上行限速模式", Value: up}
		switch up {
		case "ifb_htb":
			uit.Status = scOK
			uit.Detail = "IFB + HTB 精确整形"
		case "police":
			uit.Status = scWarn
			uit.Detail = "只能用 police 丢包式限速, 精度与体验较差"
			uit.Fix = "内核缺 IFB 或 mirred; 属机型限制"
		default:
			uit.Status = scFail
			uit.Value = "unsupported"
			uit.Detail = "上行限速不可用"
			uit.Fix = "内核缺 IFB/mirred/police; 属机型限制, 只能限下行"
		}
		items = append(items, uit)

		down := asString(caps["downlink_mode"])
		dit := scItem{ID: "downlink_mode", Label: "下行限速模式", Value: down}
		switch down {
		case "htb":
			dit.Status = scOK
		case "root_htb":
			dit.Status = scInfo
			dit.Detail = "根 HTB 兼容模式(ROM 的 mq 子队列不接受 HTB)"
		case "tbf_global":
			dit.Status = scWarn
			dit.Detail = "只能整体限速(tbf), 无法按设备区分"
		default:
			dit.Status = scFail
			dit.Detail = "下行限速不可用"
		}
		if q := asString(caps["probe_iface_qdisc"]); q != "" {
			if dit.Detail != "" {
				dit.Detail += "; "
			}
			dit.Detail += "热点口当前 qdisc: " + scShort(q, 160)
		}
		items = append(items, dit)
	}
	return items
}

// ═══ 防火墙 ═══════════════════════════════════════════════════════

type scXt struct {
	ID, Name, Label string
	Target          bool
	Kcfg            []string
	Importance      string
	Why             string
}

var scXtList = []scXt{
	{"xt_mac", "mac", "mac 匹配", false, []string{"NETFILTER_XT_MATCH_MAC"}, "required", "按 MAC 识别设备打标失败, 限速/封锁全部失效"},
	{"xt_mark", "mark", "mark 匹配", false, []string{"NETFILTER_XT_MATCH_MARK", "NETFILTER_XT_MARK"}, "recommended", "按标记分流失效"},
	{"xt_connmark", "connmark", "connmark 匹配", false, []string{"NETFILTER_XT_MATCH_CONNMARK", "NETFILTER_XT_CONNMARK"}, "recommended", "连接级标记恢复失效(IPv6 兜底路径)"},
	{"xt_conntrack", "conntrack", "conntrack 匹配", false, []string{"NETFILTER_XT_MATCH_CONNTRACK"}, "recommended", "按连接状态过滤失效"},
	{"xt_string", "string", "string 匹配", false, []string{"NETFILTER_XT_MATCH_STRING"}, "optional", "按域名字符串封锁不可用"},
	{"xt_comment", "comment", "comment 注释", false, []string{"NETFILTER_XT_MATCH_COMMENT"}, "optional", ""},
	{"xt_limit", "limit", "limit 速率", false, []string{"NETFILTER_XT_MATCH_LIMIT"}, "optional", ""},
	{"xt_MARK", "MARK", "MARK 目标", true, []string{"NETFILTER_XT_TARGET_MARK", "NETFILTER_XT_MARK"}, "required", "无法给设备流量打标"},
	{"xt_CONNMARK", "CONNMARK", "CONNMARK 目标", true, []string{"NETFILTER_XT_TARGET_CONNMARK", "NETFILTER_XT_CONNMARK"}, "recommended", ""},
	{"xt_NFLOG", "NFLOG", "NFLOG 目标", true, []string{"NETFILTER_XT_TARGET_NFLOG"}, "optional", "NFLOG 日志不可用(不影响核心功能)"},
}

func scLineSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, ln := range strings.Split(s, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			m[ln] = true
		}
	}
	return m
}

func scSectionFirewall(c *scCtx) []scItem {
	var items []scItem
	for _, b := range []struct{ id, bin, label, miss string }{
		{"iptables", "iptables", "iptables", scFail},
		{"ip6tables", "ip6tables", "ip6tables", scWarn},
	} {
		it := scItem{ID: b.id, Label: b.label}
		if out, ok := c.run(b.bin, "-V"); ok && strings.TrimSpace(out) != "" {
			it.Status, it.Value = scOK, scShort(out, 60)
		} else {
			it.Status, it.Value = b.miss, "不可用"
			it.Fix = "系统缺少 " + b.bin + " 或被拦截"
		}
		items = append(items, it)
	}

	matches, mOK := c.read("/proc/net/ip_tables_matches")
	targets, tOK := c.read("/proc/net/ip_tables_targets")
	mset, tset := scLineSet(matches), scLineSet(targets)
	kc := c.kconfig()
	for _, x := range scXtList {
		set, readable := mset, mOK
		if x.Target {
			set, readable = tset, tOK
		}
		it := scItem{ID: x.ID, Label: x.Label}
		switch {
		case set[x.Name]:
			it.Status, it.Value = scOK, "已注册"
		default:
			state := "unknown"
			if kc != nil {
				state = "no"
				for _, k := range x.Kcfg {
					if v := kc[k]; v == "y" || v == "m" {
						state = "maybe"
					}
				}
			} else if readable {
				// 已注册列表可读但没有, 且无内核配置可查: 可能是未加载的模块
				state = "unknown"
			}
			switch state {
			case "maybe":
				it.Status, it.Value = scInfo, "未注册(内核已编译, 首次使用时加载)"
			case "no":
				it.Status, it.Value = scFeatureStatus("no", x.Importance), "不支持"
				it.Detail = x.Why
			default:
				it.Status, it.Value = scInfo, "未注册/未知"
				if x.Importance == "required" {
					it.Detail = "HNC 规则尚未用到或模块未加载; 若限速失效请查看 iptables 日志"
				}
			}
		}
		items = append(items, it)
	}

	m6, _ := c.read("/proc/net/ip6_tables_matches")
	i6 := scItem{ID: "ip6_mac", Label: "IPv6 mac 匹配"}
	if scLineSet(m6)["mac"] {
		i6.Status, i6.Value = scOK, "已注册"
	} else {
		i6.Status, i6.Value = scInfo, "未注册/未知"
		i6.Detail = "ip6tables 未注册 mac 匹配时, IPv6 只能靠 tc u32 按地址限速(见「IPv6 覆盖」)"
	}
	items = append(items, i6)

	hc := scItem{ID: "hnc_chain", Label: "HNC 打标链"}
	if out, ok := c.run("iptables", "-t", "mangle", "-S", "HNC_MARK"); ok {
		n := strings.Count(out, "\n-A ") + map[bool]int{true: 1, false: 0}[strings.HasPrefix(out, "-A ")]
		hc.Status, hc.Value = scOK, fmt.Sprintf("已建立(%d 条规则)", n)
	} else {
		hc.Status, hc.Value = scInfo, "未建立"
		hc.Detail = "服务未启动或还没有限速设备"
	}
	items = append(items, hc)

	acct := c.readTrim("/proc/sys/net/netfilter/nf_conntrack_acct")
	ait := scItem{ID: "conntrack_acct", Label: "conntrack 字节计数", Value: acct}
	switch acct {
	case "1":
		ait.Status, ait.Value = scOK, "已开启"
	case "0":
		ait.Status, ait.Value = scWarn, "关闭"
		ait.Detail = "按应用流量统计缺字节数"
		ait.Fix = "httpd 启动时会尝试打开; 仍为 0 说明 ROM 拒绝写 /proc/sys/net/netfilter/nf_conntrack_acct"
	default:
		ait.Status, ait.Value = scWarn, "不可读"
		ait.Detail = "内核可能未启用 nf_conntrack"
	}
	items = append(items, ait)

	cit := scItem{ID: "conntrack_events", Label: "按应用流量模式"}
	active, lastErr := false, ""
	if c.env.CtEvents != nil {
		active, lastErr = c.env.CtEvents()
	}
	evs := c.readTrim("/proc/sys/net/netfilter/nf_conntrack_events")
	if active {
		cit.Status, cit.Value = scOK, "精确(订阅 conntrack DESTROY 事件)"
	} else {
		cit.Status, cit.Value = scInfo, "轮询(每 10 秒采样, 短连接可能少算)"
		if lastErr != "" {
			cit.Detail = "订阅失败: " + scShort(lastErr, 120)
		}
	}
	if evs != "" {
		if cit.Detail != "" {
			cit.Detail += "; "
		}
		cit.Detail += "nf_conntrack_events=" + evs
	}
	items = append(items, cit)

	ctf := scItem{ID: "conntrack_table", Label: "连接表可读"}
	if c.env.Exists("/proc/net/nf_conntrack") {
		ctf.Status, ctf.Value = scOK, "是"
	} else {
		ctf.Status, ctf.Value = scWarn, "否"
		ctf.Detail = "/proc/net/nf_conntrack 不存在, 实时连接/按应用流量不可用"
	}
	items = append(items, ctf)
	return items
}

// ═══ 硬件加速 ═════════════════════════════════════════════════════

var (
	scMtkModRE     = regexp.MustCompile(`(?i)hnat|hw_nat|mtk_ppe|mddp|mtk_hwnat`)
	scQcomAggModRE = regexp.MustCompile(`^(rmnet_offload|rmnet_perf_tether)$`)
	scQcomModRE    = regexp.MustCompile(`(?i)^ipa|rmnet_ipa|ipam$|rmnet_offload|rmnet_shs|rmnet_perf`)
	scSamsungModRE = regexp.MustCompile(`(?i)linkforward|link_forward`)
	scUnisocModRE  = regexp.MustCompile(`(?i)sipa`)
)

func scSectionOffload(c *scCtx) []scItem {
	var items []scItem
	g := c.readJSON(c.hnc("run", "offload_guard.json"))
	git := scItem{ID: "offload_guard", Label: "offload 兜底"}
	state := ""
	if g == nil {
		// 守护没跑: 退回一次 check_offload.sh(含 5s 采样, 在本分区 goroutine 里并发)
		script := c.hnc("bin", "check_offload.sh")
		if c.env.Exists(script) {
			cctx, cancel := context.WithTimeout(c.ctx, 9*time.Second)
			out, _ := c.env.Run(cctx, "sh", script)
			cancel()
			state = strings.TrimSpace(lastLine(out))
		}
		git.Status, git.Value = scInfo, "守护未运行"
		if state != "" {
			git.Value += ", 本次采样: " + state
		}
	} else {
		state = asString(g["offload_state"])
		fb, _ := g["fallback_active"].(bool)
		mode := asString(g["mode"])
		git.Value = fmt.Sprintf("模式 %s · 状态 %s · 兜底%s", mode, state, map[bool]string{true: "生效", false: "未生效"}[fb])
		git.Detail = asString(g["detail"])
		if lc, ok := toInt64(g["last_check"]); ok && lc > 0 {
			git.Detail += fmt.Sprintf("; %s前采样", scDur(c.env.Now().Unix()-lc))
		}
		switch {
		case state == "ACTIVE" && !fb:
			git.Status = scWarn
			git.Fix = "offload 正在旁路限速, 把设置里的 offload 兜底改为 auto 或 on"
		case state == "ACTIVE" && fb:
			git.Status = scOK
		case state == "SKIPPED" || mode == "off":
			git.Status = scInfo
		default:
			git.Status = scOK
		}
	}
	items = append(items, git)

	tb := scItem{ID: "tether_bpf", Label: "AOSP tether BPF"}
	if names, err := c.env.ReadDir("/sys/fs/bpf/tethering"); err == nil {
		n := 0
		for _, x := range names {
			if strings.Contains(x, "tether") || strings.Contains(x, "offload") {
				n++
			}
		}
		tb.Status, tb.Value = scInfo, fmt.Sprintf("存在(%d 个 map/prog)", n)
		tb.Detail = "系统具备 BPF 热点转发加速; 是否旁路限速以上面 offload 兜底的实测状态为准"
	} else {
		tb.Status, tb.Value = scOK, "不存在"
		tb.Detail = "非 GKI 或未启用 tether offload, 不会旁路 tc"
	}
	items = append(items, tb)

	vendor := scSoCVendor(c.allProps())

	var qd []string
	for _, p := range []string{"/dev/ipa", "/sys/class/net/rmnet_ipa0", "/vendor/bin/ipacm"} {
		if c.env.Exists(p) {
			qd = append(qd, p)
		}
	}
	if out, ok := c.run("pidof", "ipacm"); ok && strings.TrimSpace(out) != "" {
		qd = append(qd, "ipacm 运行中")
	}
	qd = append(qd, c.moduleMatching(scQcomModRE)...)
	if len(qd) > 0 || vendor == "qualcomm" {
		it := scItem{ID: "qcom_ipa", Label: "高通 IPA 硬件加速", Status: scInfo}
		if len(qd) > 0 {
			it.Value = "检测到"
			it.Detail = strings.Join(qd, ", ") + "; IPA 可能把热点流量直接交给基带转发, 若限速失效请看 offload 兜底状态"
		} else {
			it.Value = "未检测到"
		}
		items = append(items, it)
	}
	// v5.20.1: IPA 硬件转发 + rmnet_offload / rmnet_perf_tether 时, 部分热点字节可能不过内核计数点
	if agg := c.moduleMatching(scQcomAggModRE); len(qd) > 0 && len(agg) > 0 {
		items = append(items, scItem{ID: "hotspot_counter_bypass", Label: "热点字节计数旁路", Status: scInfo,
			Value: "可能存在",
			Detail: "检测到 IPA + " + strings.Join(agg, ",") + ": 硬件/聚合快速路径转发的热点流量可能不经过热点口的内核计数" +
				"(/proc/net/dev、iptables、tc 统计), 热点用量与限速统计可能偏小; 本项只是提示, 未实测",
			Fix: "对比系统「数据使用」里的热点用量; 偏差明显时使用统计校准功能(开发中)"})
	}

	var md []string
	for _, p := range []string{"/sys/kernel/debug/hnat", "/proc/hnat", "/sys/kernel/debug/mtk_ppe", "/dev/mddp", "/proc/mddp", "/sys/kernel/mddp"} {
		if c.env.Exists(p) {
			md = append(md, p)
		}
	}
	md = append(md, c.moduleMatching(scMtkModRE)...)
	// bin/hnc_mtk_hwnat.sh 的检测/处置结果(有则复用, 不重复探测)
	hw := c.readJSON(c.hnc("run", "mtk_hwnat.json"))
	hwDetected, _ := hw["detected"].(bool)
	if len(md) > 0 || vendor == "mediatek" || hwDetected {
		it := scItem{ID: "mtk_hwnat", Label: "联发科 HWNAT/MDDP", Status: scInfo}
		if len(md) > 0 || hwDetected {
			it.Value = "检测到"
			it.Detail = strings.Join(md, ", ") + "; MDDP/HWNAT 会让热点数据绕过内核协议栈, 可能导致限速/统计失效"
			if state == "ACTIVE" {
				it.Status = scWarn
			}
		} else {
			it.Value = "未检测到"
		}
		if hw != nil {
			act := asString(hw["action"])
			it.Detail = strings.TrimPrefix(it.Detail+"; hnc_mtk_hwnat: "+act, "; ")
			if d := asString(hw["detail"]); d != "" {
				it.Detail += "(" + scShort(d, 100) + ")"
			}
			switch act {
			case "disabled":
				it.Status = scOK
				it.Value = "检测到, 已由 HNC 关闭"
			case "failed":
				it.Status = scWarn
			}
		}
		items = append(items, it)
	}

	if vendor == "samsung" {
		sm := c.moduleMatching(scSamsungModRE)
		it := scItem{ID: "samsung_offload", Label: "三星转发加速", Status: scInfo, Value: "未检测到"}
		if len(sm) > 0 {
			it.Value = "检测到"
			it.Detail = strings.Join(sm, ", ")
		} else {
			it.Detail = "Exynos 未见公开的转发加速接口, 以 tether BPF / offload 兜底状态为准"
		}
		items = append(items, it)
	}
	if vendor == "unisoc" {
		um := c.moduleMatching(scUnisocModRE)
		it := scItem{ID: "unisoc_sipa", Label: "展锐 SIPA 加速", Status: scInfo, Value: "未检测到"}
		if len(um) > 0 || c.env.Exists("/dev/sipa_dummy") {
			it.Value = "检测到"
			it.Detail = strings.Join(um, ", ")
		}
		items = append(items, it)
	}
	return items
}

// ═══ 热点与网络 ═══════════════════════════════════════════════════

// 接口分类复用 iface_patterns.go(与 bin/hnc_iface.sh 同一份表), 不另立正则。
func scIsHotspotCandidate(n string) bool {
	return isAPIfaceName(n) || hncAPMaybeIfaceRE.MatchString(n) || hncUSBTetherRE.MatchString(n) || hncBTTetherRE.MatchString(n)
}

var (
	scTetherIfRE = regexp.MustCompile(`^\s*(\S+) - (\w+State)\b`)
	scUpstreamRE = regexp.MustCompile(`(?i)current upstream interface\(s\):\s*(.+)`)
)

// scParseTethering `dumpsys tethering` → (被共享口列表, 上游描述)
func scParseTethering(out string) ([]string, string) {
	var tethered []string
	up := ""
	for _, ln := range strings.Split(out, "\n") {
		if m := scTetherIfRE.FindStringSubmatch(ln); m != nil {
			if m[2] == "TetheredState" || m[2] == "LocalHotspotState" {
				tethered = append(tethered, m[1])
			}
		}
		if up == "" {
			if m := scUpstreamRE.FindStringSubmatch(ln); m != nil {
				up = strings.TrimSpace(m[1])
			}
		}
	}
	return tethered, up
}

// scFirstUpstreamIface "[rmnet_data3, v4-rmnet_data3]" → "rmnet_data3"(跳过 clat v4-*)
func scFirstUpstreamIface(desc string) string {
	f := strings.FieldsFunc(desc, func(r rune) bool { return r == '[' || r == ']' || r == ',' || r == ' ' || r == '\t' })
	for _, n := range f {
		if n != "" && n != "null" && !strings.HasPrefix(n, "v4-") && ifaceNameOK(n) {
			return n
		}
	}
	return ""
}

// readIfaceDetectFrom 经 scEnv 读 run/iface_detect.json(测试可注入)
func readIfaceDetectFrom(c *scCtx) ifaceDetect {
	var d ifaceDetect
	b, err := c.env.ReadFile(c.hnc("run", "iface_detect.json"))
	if err != nil || json.Unmarshal(b, &d) != nil {
		return ifaceDetect{}
	}
	return d
}

func scUpClassName(n string) string {
	switch {
	case n == "":
		return ""
	case isVPNIface(n):
		return "VPN"
	case isCellIface(n):
		return "蜂窝"
	case n == "wlan0":
		return "Wi-Fi"
	case hncUSBTetherRE.MatchString(n):
		return "USB"
	case strings.HasPrefix(n, "eth"):
		return "以太网"
	}
	return ""
}

func scWithClass(n string) string {
	if cl := scUpClassName(n); cl != "" {
		return n + "(" + cl + ")"
	}
	return n
}

// scUpstreamItem v5.20.1: 热点上游(tethering)与本机出口(可能是 VPN)分开显示。
// 例: "热点上游 rmnet_data3(蜂窝) · 本机走 VPN tun0"
func scUpstreamItem(local, tetherUp string, det ifaceDetect) scItem {
	it := scItem{ID: "upstream", Label: "上游出口", Status: scOK}
	if tetherUp == "" && det.TetherUpstream != "" && !isVPNIface(det.TetherUpstream) {
		tetherUp = det.TetherUpstream
	}
	vpn := isVPNIface(local) || det.VPNActive
	phys := ""
	if vpn && det.Upstream != "" && !isVPNIface(det.Upstream) {
		phys = det.Upstream // hnc_iface.sh: VPN 下带 default route 的物理口
	}
	var parts []string
	if tetherUp != "" {
		parts = append(parts, "热点上游 "+scWithClass(tetherUp))
	}
	switch {
	case vpn && local != "":
		s := "本机走 VPN " + local
		if tetherUp == "" && phys != "" {
			s += "(物理出口 " + scWithClass(phys) + ")"
		}
		parts = append(parts, s)
	case vpn:
		parts = append(parts, "本机走 VPN")
	case local != "" && tetherUp == "":
		parts = append(parts, local)
	case local != "" && local != tetherUp && strings.TrimPrefix(local, "v4-") != tetherUp:
		parts = append(parts, "本机出口 "+scWithClass(local))
	}
	if len(parts) == 0 {
		it.Status, it.Value = scWarn, "无默认路由"
		it.Detail = "手机当前没有可用的上网出口"
		return it
	}
	it.Value = strings.Join(parts, " · ")
	if vpn {
		it.Detail = "手机开着 VPN: 本机流量经 VPN 隧道(字节计在承载它的物理口上), 热点客户端流量走系统共享上游、不经过手机 VPN; 本月流量按热点上游拆分"
	}
	return it
}

func scSectionNetwork(c *scCtx) []scItem {
	var items []scItem
	ifc := c.hotspotIface()
	state := c.readTrim(c.hnc("run", "hnc_state"))
	hit := scItem{ID: "hotspot_iface", Label: "热点接口"}
	switch {
	case ifc == "":
		hit.Status, hit.Value = scInfo, "未识别"
		hit.Detail = "热点未开启或尚未识别到接口"
	case !c.env.Exists("/sys/class/net/" + ifc):
		hit.Status, hit.Value = scWarn, ifc+"(接口不存在)"
		hit.Detail = "记录的热点口已消失(热点已关闭?)"
		hit.Fix = "开启热点后重新自检; 接口识别错误可在设置里手动指定热点接口"
	default:
		ost := c.operstate(ifc)
		hit.Value = ifc + "(" + ost + ")"
		hit.Status = scOK
		if ost == "down" {
			hit.Status = scInfo
		}
	}
	if state != "" {
		hit.Detail = strings.TrimSpace(hit.Detail + " hnc_state=" + scShort(state, 60))
	}
	items = append(items, hit)

	var cands, cell []string
	for _, n := range c.netIfaces() {
		if scIsHotspotCandidate(n) {
			cands = append(cands, n+"("+c.operstate(n)+")")
		}
		if isCellIface(n) {
			if ost := c.operstate(n); ost == "up" || ost == "unknown" {
				cell = append(cell, n)
			}
		}
	}
	items = append(items, scItem{ID: "iface_candidates", Label: "候选热点接口", Status: scInfo,
		Value: strings.Join(cands, ", ")})

	local := ""
	if out, ok := c.run("ip", "route", "get", "1.1.1.1"); ok {
		local = puParseRouteGet(out)
	}
	tethOut, tethOK := c.run("dumpsys", "tethering")
	tetherUp := ""
	if tethOK {
		_, desc := scParseTethering(tethOut)
		tetherUp = scFirstUpstreamIface(desc)
	}
	items = append(items, scUpstreamItem(local, tetherUp, readIfaceDetectFrom(c)))

	tit := scItem{ID: "tethering", Label: "系统共享状态", Status: scInfo}
	if out, ok := tethOut, tethOK; ok && out != "" {
		tethered, up := scParseTethering(out)
		if len(tethered) > 0 {
			tit.Value = "共享中: " + strings.Join(tethered, ", ")
		} else {
			tit.Value = "未共享"
		}
		if up != "" {
			tit.Detail = "系统上游: " + scShort(up, 120)
		}
	} else {
		tit.Value = "dumpsys tethering 不可用"
	}
	items = append(items, tit)

	cit := scItem{ID: "cellular", Label: "蜂窝接口", Status: scInfo, Value: strings.Join(cell, ", ")}
	if len(cell) == 0 {
		cit.Value = "无活动蜂窝接口"
	}
	items = append(items, cit)

	msc := strings.ToLower(c.prop("persist.radio.multisim.config"))
	alpha := puParseAlpha(c.prop("gsm.sim.operator.alpha"))
	subID := 0
	if out, ok := c.run("settings", "get", "global", "multi_sim_data_call"); ok {
		subID = puParseSubID(out)
	}
	sim := puResolveSIM(subID, "settings", nil, alpha)
	nSIM := 0
	for _, a := range alpha {
		if a != "" {
			nSIM++
		}
	}
	sit := scItem{ID: "dual_sim", Label: "SIM 卡", Status: scInfo}
	switch msc {
	case "dsds", "dsda", "tsts":
		sit.Value = fmt.Sprintf("双卡设备(%s), 已插 %d 张", msc, nSIM)
	default:
		sit.Value = fmt.Sprintf("已插 %d 张", nSIM)
	}
	if sim.Slot > 0 {
		sit.Value += fmt.Sprintf(" · 数据卡: 卡%d %s", sim.Slot, sim.Carrier)
	}
	sit.Detail = fmt.Sprintf("运营商: %s; 默认数据 subId=%d", strings.Join(alpha, " / "), subID)
	items = append(items, sit)

	vit := scItem{ID: "hotspot_ipv6", Label: "热点 IPv6", Status: scInfo}
	if ifc != "" && c.env.Exists("/sys/class/net/"+ifc) {
		out, _ := c.run("ip", "-6", "addr", "show", "dev", ifc)
		g := 0
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "inet6") && strings.Contains(ln, "scope global") {
				g++
			}
		}
		dis := c.readTrim("/proc/sys/net/ipv6/conf/" + ifc + "/disable_ipv6")
		fwd := c.readTrim("/proc/sys/net/ipv6/conf/all/forwarding")
		if g > 0 {
			vit.Status, vit.Value = scOK, fmt.Sprintf("已下发(热点口 %d 个全局地址)", g)
		} else {
			vit.Value = "未下发"
			vit.Detail = "客户端只走 IPv4, IPv6 限速不涉及"
		}
		if dis == "1" {
			vit.Value = "热点口禁用 IPv6"
		}
		vit.Detail = strings.TrimSpace(vit.Detail + " forwarding=" + fwd)
	} else {
		vit.Value = "热点未开启"
	}
	items = append(items, vit)

	wit := scItem{ID: "softap_cmd", Label: "定时热点命令"}
	out, _ := c.run("cmd", "wifi", "help")
	switch {
	case strings.Contains(out, "start-softap"):
		wit.Status, wit.Value = scOK, "支持 cmd wifi start-softap"
	case strings.TrimSpace(out) != "":
		wit.Status, wit.Value = scWarn, "cmd wifi 无 start-softap"
		wit.Detail = "定时开热点只能用备用方式, 可能不生效"
	default:
		wit.Status, wit.Value = scWarn, "cmd wifi 不可用"
		wit.Detail = "定时开/关热点可能无法自动执行"
		wit.Fix = "ColorOS 等 ROM 可能拦截, 需真机验证; 定时关热点仍可用"
	}
	items = append(items, wit)
	return items
}

// ═══ IPv6 覆盖 ════════════════════════════════════════════════════

// scParseNeighV6 `ip -6 neigh show dev X` → mac → 全局地址(去 fe80 / FAILED / INCOMPLETE)
func scParseNeighV6(out string) map[string][]string {
	res := map[string][]string{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 || !strings.Contains(f[0], ":") || strings.HasPrefix(strings.ToLower(f[0]), "fe80") {
			continue
		}
		st := strings.ToUpper(f[len(f)-1])
		if st == "FAILED" || st == "INCOMPLETE" || st == "NOARP" {
			continue
		}
		mac := ""
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				mac = strings.ToLower(f[i+1])
			}
		}
		if mac == "" || !validMAC(mac) {
			continue
		}
		ip := scCanonIP6(f[0])
		if ip == "" {
			continue
		}
		dup := false
		for _, x := range res[mac] {
			dup = dup || x == ip
		}
		if !dup {
			res[mac] = append(res[mac], ip)
		}
	}
	for k := range res {
		sort.Strings(res[k])
	}
	return res
}

func scCanonIP6(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return ""
	}
	return ip.String()
}

var scMarkRuleRE = regexp.MustCompile(`--mac-source\s+(\S+).*--set-x?mark\s+(0x[0-9a-fA-F]+|\d+)`)

// scParseMarkRules `iptables -t mangle -S HNC_MARK` → mac → mark 值
func scParseMarkRules(out string) map[string]int64 {
	res := map[string]int64{}
	for _, ln := range strings.Split(out, "\n") {
		m := scMarkRuleRE.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		v, err := strconv.ParseInt(m[2], 0, 64)
		if err != nil {
			continue
		}
		mac := strings.ToLower(m[1])
		if _, ok := res[mac]; !ok {
			res[mac] = v
		}
	}
	return res
}

type scV6Filter struct {
	Addr   string
	Dir    string // src | dst
	FlowID string
	Pref   string
}

var (
	scFilterHdrRE = regexp.MustCompile(`^filter .*protocol (ipv6|all)\b.*\bpref (\d+)\b.*\bfh (\S+)`)
	scFlowIDRE    = regexp.MustCompile(`\bflowid (\S+)`)
	scU32MatchRE  = regexp.MustCompile(`^\s*match ([0-9a-fA-F]{8})/([0-9a-fA-F]{8}) at (\d+)`)
)

// scParseTCv6Filters 从 `tc filter show dev X parent 1:` 里还原 u32 的 ip6 src/dst /128 匹配。
// iproute2 把 "match ip6 dst A/128" 打成 4 行 "match XXXXXXXX/ffffffff at 24|28|32|36"
// (src 在 8..20)。只收四段齐全且全掩码的(即 v6_sync.sh 装的 /128)。
func scParseTCv6Filters(out string) []scV6Filter {
	var res []scV6Filter
	type cur struct {
		pref, flow string
		v6         bool
		words      map[int]string
	}
	var c *cur
	flush := func() {
		if c == nil || !c.v6 {
			return
		}
		for _, d := range []struct {
			dir  string
			base int
		}{{"src", 8}, {"dst", 24}} {
			var sb strings.Builder
			ok := true
			for k := 0; k < 4; k++ {
				w, has := c.words[d.base+4*k]
				if !has {
					ok = false
					break
				}
				sb.WriteString(w)
			}
			if !ok {
				continue
			}
			hex := sb.String()
			var parts []string
			for k := 0; k < 32; k += 4 {
				parts = append(parts, hex[k:k+4])
			}
			if ip := scCanonIP6(strings.Join(parts, ":")); ip != "" {
				res = append(res, scV6Filter{Addr: ip, Dir: d.dir, FlowID: c.flow, Pref: c.pref})
			}
		}
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "filter ") {
			flush()
			c = nil
			if m := scFilterHdrRE.FindStringSubmatch(ln); m != nil {
				fm := scFlowIDRE.FindStringSubmatch(ln)
				if fm == nil {
					continue // 哈希表头行("fh 800: ht divisor 1"), 无 flowid
				}
				c = &cur{pref: m[2], flow: fm[1], v6: m[1] == "ipv6", words: map[int]string{}}
			}
			continue
		}
		if c == nil {
			continue
		}
		if m := scU32MatchRE.FindStringSubmatch(ln); m != nil && strings.EqualFold(m[2], "ffffffff") {
			off, _ := strconv.Atoi(m[3])
			c.words[off] = strings.ToLower(m[1])
		}
	}
	flush()
	return res
}

type scV6Dev struct {
	MAC        string
	Addrs      []string
	Mark       int64
	Class      string // 1:<cls>
	UpLimited  bool   // ifb0 上有该 class
	DownMiss   []string
	DownWrong  []string // 有 filter 但 flowid 指向别的 class
	UpMiss     []string
	Limited    bool
	IP6TMarked bool
}

// scIPv6Coverage 纯函数: 邻居表 × 打标规则 × tc filter → 每台限速设备的 v6 覆盖
func scIPv6Coverage(neigh map[string][]string, marks map[string]int64, ip6marks map[string]int64,
	egress, ingress []scV6Filter, ifbClasses map[string]bool, markBase int64) []scV6Dev {
	eg := map[string]string{}
	for _, f := range egress {
		if f.Dir == "dst" {
			eg[f.Addr] = f.FlowID
		}
	}
	in := map[string]string{}
	for _, f := range ingress {
		if f.Dir == "src" {
			in[f.Addr] = f.FlowID
		}
	}
	var macs []string
	for m := range neigh {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	var res []scV6Dev
	for _, mac := range macs {
		d := scV6Dev{MAC: mac, Addrs: neigh[mac]}
		_, d.IP6TMarked = ip6marks[mac]
		mk, ok := marks[mac]
		id := mk - markBase
		if !ok || id < 1 || id > 99 {
			res = append(res, d)
			continue
		}
		d.Limited, d.Mark = true, mk
		cls := id
		if id == 1 {
			cls = 100
		}
		d.Class = "1:" + strconv.FormatInt(cls, 10)
		d.UpLimited = ifbClasses[d.Class]
		for _, a := range d.Addrs {
			switch fl, has := eg[a]; {
			case !has:
				d.DownMiss = append(d.DownMiss, a)
			case fl != d.Class:
				d.DownWrong = append(d.DownWrong, a)
			}
			if d.UpLimited {
				if fl, has := in[a]; !has || fl != d.Class {
					d.UpMiss = append(d.UpMiss, a)
				}
			}
		}
		res = append(res, d)
	}
	return res
}

var scClassRE = regexp.MustCompile(`class \S+ (\d+:[0-9a-fA-F]+)`)

func scParseClasses(out string) map[string]bool {
	res := map[string]bool{}
	for _, m := range scClassRE.FindAllStringSubmatch(out, -1) {
		res[m[1]] = true
	}
	return res
}

func (c *scCtx) markBase() int64 {
	s, _ := c.read(c.hnc("bin", "hnc_constants.sh"))
	if m := regexp.MustCompile(`HNC_MARK_BASE=["']?(0x[0-9a-fA-F]+)`).FindStringSubmatch(s); m != nil {
		if v, err := strconv.ParseInt(m[1], 0, 64); err == nil {
			return v
		}
	}
	return 0x800000
}

func scSectionIPv6(c *scCtx) []scItem {
	ifc := c.hotspotIface()
	if ifc == "" || !c.env.Exists("/sys/class/net/"+ifc) {
		return []scItem{{ID: "v6_neigh", Label: "IPv6 邻居", Status: scInfo, Value: "热点未开启, 跳过"}, c.v6NeighSubItem()}
	}
	out, ok := c.run("ip", "-6", "neigh", "show", "dev", ifc)
	if !ok || strings.TrimSpace(out) == "" {
		out, _ = c.run("ip", "neigh", "show", "dev", ifc)
	}
	neigh := scParseNeighV6(out)
	mo, _ := c.run("iptables", "-t", "mangle", "-S", "HNC_MARK")
	m6, _ := c.run("ip6tables", "-t", "mangle", "-S", "HNC_MARK")
	eo, _ := c.run("tc", "filter", "show", "dev", ifc, "parent", "1:")
	io, _ := c.run("tc", "filter", "show", "dev", "ifb0", "parent", "1:")
	co, _ := c.run("tc", "class", "show", "dev", "ifb0")
	devs := scIPv6Coverage(neigh, scParseMarkRules(mo), scParseMarkRules(m6),
		scParseTCv6Filters(eo), scParseTCv6Filters(io), scParseClasses(co), c.markBase())

	var items []scItem
	limited, withV6, miss, i6t := 0, len(devs), 0, 0
	for _, d := range devs {
		if d.IP6TMarked {
			i6t++
		}
		if !d.Limited {
			continue
		}
		limited++
		n := len(d.Addrs)
		it := scItem{ID: "v6_dev_" + strings.ReplaceAll(d.MAC, ":", ""), Label: "设备 " + d.MAC, Status: scOK}
		downOK := n - len(d.DownMiss) - len(d.DownWrong)
		it.Value = fmt.Sprintf("下行 %d/%d", downOK, n)
		if d.UpLimited {
			it.Value += fmt.Sprintf(" · 上行 %d/%d", n-len(d.UpMiss), n)
		} else {
			it.Value += " · 上行未限速"
		}
		var det []string
		if len(d.DownMiss) > 0 {
			det = append(det, "下行未覆盖: "+strings.Join(d.DownMiss, " "))
		}
		if len(d.DownWrong) > 0 {
			det = append(det, "下行指向错误 class: "+strings.Join(d.DownWrong, " "))
		}
		if len(d.UpMiss) > 0 {
			det = append(det, "上行未覆盖: "+strings.Join(d.UpMiss, " "))
		}
		bad := len(d.DownMiss) + len(d.DownWrong) + len(d.UpMiss)
		miss += bad
		if bad > 0 {
			it.Status = scWarn
			it.Fix = "新地址出现后约 1 秒自动补上(另有每 60 秒兜底同步); 持续未覆盖请看 run/v6_neigh.json 的 active 是否为 true, 或在设置里「刷新规则」后重新自检"
		}
		det = append(det, fmt.Sprintf("class %s, mark 0x%x", d.Class, d.Mark))
		if d.IP6TMarked {
			det = append(det, "ip6tables MAC 打标兜底: 有")
		}
		it.Detail = strings.Join(det, "; ")
		items = append(items, it)
	}
	sum := scItem{ID: "v6_neigh", Label: "IPv6 邻居", Status: scInfo,
		Value:  fmt.Sprintf("%d 台设备有 IPv6 全局地址, 其中 %d 台已限速", withV6, limited),
		Detail: fmt.Sprintf("ip6tables MAC 打标设备: %d 台", i6t)}
	cov := scItem{ID: "v6_uncovered", Label: "未覆盖的 IPv6 地址"}
	switch {
	case limited == 0:
		cov.Status, cov.Value = scInfo, "无需覆盖(没有带 IPv6 的限速设备)"
	case miss == 0:
		cov.Status, cov.Value = scOK, "0"
	default:
		cov.Status, cov.Value = scWarn, strconv.Itoa(miss)
		cov.Detail = "这些地址的流量会绕过限速(走默认类)"
		cov.Fix = "见下方各设备明细"
	}
	return append([]scItem{sum, cov, c.v6NeighSubItem()}, items...)
}

// v6NeighSubItem v5.20.1: run/v6_neigh.json(neigh_v6.go)—— 新 IPv6 地址事件订阅状态
func (c *scCtx) v6NeighSubItem() scItem {
	it := scItem{ID: "v6_neigh_sub", Label: "邻居事件订阅"}
	m := c.readJSON(c.hnc("run", "v6_neigh.json"))
	if m == nil {
		it.Status, it.Value = scInfo, "无状态"
		it.Detail = "run/v6_neigh.json 不存在(httpd 刚启动或热点未开); 60 秒兜底同步不受影响"
		return it
	}
	active, _ := m["active"].(bool)
	ev, _ := toInt64(m["events"])
	tr, _ := toInt64(m["triggers"])
	last, _ := toInt64(m["last_run_at"])
	var det []string
	if last > 0 {
		d := fmt.Sprintf("最近一次同步 %s前", scDur(c.env.Now().Unix()-last))
		if rc, ok := toInt64(m["last_rc"]); ok && rc != 0 {
			d += fmt.Sprintf("(退出码 %d)", rc)
		}
		det = append(det, d)
	} else {
		det = append(det, "尚未触发过同步")
	}
	if e := asString(m["err"]); e != "" {
		det = append(det, "错误: "+scShort(e, 120))
	}
	if active {
		it.Status = scOK
		it.Value = fmt.Sprintf("在线 · 事件 %d · 触发 %d", ev, tr)
		if rc, ok := toInt64(m["last_rc"]); ok && rc != 0 && last > 0 {
			it.Status = scWarn
		}
	} else {
		it.Status = scWarn
		it.Value = fmt.Sprintf("离线 · 事件 %d · 触发 %d", ev, tr)
		it.Fix = "新地址改由每 60 秒兜底同步覆盖(最长 1 分钟绕过限速); 在设置里「重启服务」可重新订阅"
	}
	it.Detail = strings.Join(det, "; ")
	return it
}

// ═══ 时间 ═════════════════════════════════════════════════════════

func scSectionTime(c *scCtx) []scItem {
	var items []scItem
	now := c.env.Now()
	cit := scItem{ID: "clock", Label: "系统时间", Value: now.Format("2006-01-02 15:04:05 -0700"), Status: scOK}
	if now.Year() < 2025 {
		cit.Status = scFail
		cit.Detail = "系统时间明显错误"
		cit.Fix = "打开「自动确定日期和时间」并联网; 时间错误会导致证书校验失败、统计按天错乱"
	}
	items = append(items, cit)

	tz := c.prop("persist.sys.timezone")
	zn, off := now.Zone()
	tit := scItem{ID: "timezone", Label: "时区", Status: scOK, Value: fmt.Sprintf("%s(%s UTC%+d)", tz, zn, off/3600)}
	if tz == "" {
		tit.Status = scWarn
		tit.Value = fmt.Sprintf("未知(%s UTC%+d)", zn, off/3600)
		tit.Detail = "persist.sys.timezone 为空, 「今日」统计可能按 UTC 切日"
	}
	items = append(items, tit)

	ait := scItem{ID: "auto_time", Label: "自动时间"}
	out, ok := c.run("settings", "get", "global", "auto_time")
	switch strings.TrimSpace(out) {
	case "1":
		ait.Status, ait.Value = scOK, "开启"
	case "0":
		ait.Status, ait.Value = scWarn, "关闭"
		ait.Fix = "建议打开「自动确定日期和时间」, 避免定时规则/配额按错误时间执行"
	default:
		ait.Status, ait.Value = scInfo, "未知"
		if !ok {
			ait.Detail = "settings 命令不可用"
		}
	}
	if z, ok := c.run("settings", "get", "global", "auto_time_zone"); ok {
		ait.Detail = strings.TrimSpace(ait.Detail + " 自动时区=" + strings.TrimSpace(z))
	}
	items = append(items, ait)

	items = append(items, c.clockGuardItem())

	up := scItem{ID: "uptime", Label: "开机时长", Status: scInfo}
	if f := strings.Fields(c.readTrim("/proc/uptime")); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			up.Value = scDur(int64(v))
		}
	}
	if up.Value == "" {
		up.Value = "未知"
	}
	items = append(items, up)
	return items
}

// clockGuardItem v5.20.1: run/clock_state.json(clock_guard.go, 可信性变化/跳变时写)
func (c *scCtx) clockGuardItem() scItem {
	it := scItem{ID: "clock_guard", Label: "时钟守护"}
	m := c.readJSON(c.hnc("run", "clock_state.json"))
	if m == nil {
		it.Status, it.Value = scInfo, "未记录"
		it.Detail = "run/clock_state.json 不存在(守护尚未运行; 只在时钟可信性变化或跳变时写)"
		return it
	}
	sane, _ := m["sane"].(bool)
	jumps, _ := toInt64(m["jumps"])
	var det []string
	if hw, _ := toInt64(m["high_water"]); hw > 0 {
		det = append(det, "高水位 "+time.Unix(hw, 0).In(c.env.Now().Location()).Format("2006-01-02 15:04"))
	}
	if jumps > 0 {
		at, _ := toInt64(m["last_jump_at"])
		dl, _ := toInt64(m["last_jump_secs"])
		det = append(det, fmt.Sprintf("检测到 %d 次时间跳变, 最近一次 %s前(跳了 %+d 秒), 统计已重建基线", jumps, scDur(c.env.Now().Unix()-at), dl))
	}
	if sane {
		it.Status, it.Value = scOK, "时钟可信"
		if jumps > 0 {
			it.Status = scInfo
			it.Value = fmt.Sprintf("时钟可信 · 跳变 %d 次", jumps)
		}
	} else {
		it.Status, it.Value = scWarn, "时钟不可信, 按天统计已暂停"
		it.Fix = "打开「自动确定日期和时间」并联网, 时钟恢复后自动继续"
	}
	it.Detail = strings.Join(det, "; ")
	return it
}

// ═══ 进程与资源 ═══════════════════════════════════════════════════

type scProcDef struct {
	ID, Label, Key string // Key: cmdline 必含的子串(防 PID 复用)
	PIDFiles       []string
	Pidof          string
	Missing        string // 进程不在时的状态
	Why            string
}

var scProcDefs = []scProcDef{
	{"proc_httpd", "hnc_httpd", "httpd", []string{"httpd.pid"}, "", scFail, ""},
	{"proc_hotspotd", "hotspotd", "hotspotd", []string{"hotspotd.pid"}, "hotspotd", scFail, "设备发现/流量统计停止"},
	{"proc_dpid", "hnc_dpid", "dpid", []string{"dpid.child.pid", "dpid.pid"}, "hnc_dpid", scWarn, "应用识别停止"},
	{"proc_watchdog", "watchdog", "watchdog", []string{"watchdog.pid"}, "hnc_watchdog", scWarn, "规则掉了不会自动恢复"},
}

// scParseProcStat /proc/<pid>/stat → utime+stime(ticks)。comm 可含空格/括号, 从最后一个 ')' 后切。
func scParseProcStat(s string) (uint64, bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	// f[0]=state(字段3) → utime=字段14 → f[11], stime=f[12]
	if len(f) < 13 {
		return 0, false
	}
	u, e1 := strconv.ParseUint(f[11], 10, 64)
	st, e2 := strconv.ParseUint(f[12], 10, 64)
	if e1 != nil || e2 != nil {
		return 0, false
	}
	return u + st, true
}

func scParseVmRSS(status string) int64 {
	for _, ln := range strings.Split(status, "\n") {
		if strings.HasPrefix(ln, "VmRSS:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return n
			}
		}
	}
	return 0
}

func (c *scCtx) procAlive(pid int, key string) bool {
	if pid <= 0 {
		return false
	}
	if _, ok := c.read(fmt.Sprintf("/proc/%d/stat", pid)); !ok {
		return false
	}
	cl, _ := c.read(fmt.Sprintf("/proc/%d/cmdline", pid))
	cl = strings.ReplaceAll(cl, "\x00", " ")
	return strings.TrimSpace(cl) == "" || strings.Contains(cl, key)
}

// findPID pidfile(校验 cmdline)→ pidof
func (c *scCtx) findPID(d scProcDef) int {
	if d.ID == "proc_httpd" && c.env.SelfPID > 0 {
		return c.env.SelfPID
	}
	for _, f := range d.PIDFiles {
		if pid, err := strconv.Atoi(strings.TrimSpace(c.readTrim(c.hnc("run", f)))); err == nil && c.procAlive(pid, d.Key) {
			return pid
		}
	}
	if d.Pidof != "" {
		if out, ok := c.run("pidof", d.Pidof); ok {
			if f := strings.Fields(out); len(f) > 0 {
				if pid, err := strconv.Atoi(f[0]); err == nil && c.procAlive(pid, d.Key) {
					return pid
				}
			}
		}
	}
	return 0
}

func scSectionProcess(c *scCtx) []scItem {
	pids := make([]int, len(scProcDefs))
	t1 := make([]uint64, len(scProcDefs))
	for i, d := range scProcDefs {
		pids[i] = c.findPID(d)
		if pids[i] > 0 {
			s, _ := c.read(fmt.Sprintf("/proc/%d/stat", pids[i]))
			t1[i], _ = scParseProcStat(s)
		}
	}
	start := c.env.Now()
	c.env.Sleep(c.ctx, time.Second)
	el := c.env.Now().Sub(start).Seconds()
	if el <= 0 {
		el = 1
	}
	var items []scItem
	for i, d := range scProcDefs {
		it := scItem{ID: d.ID, Label: d.Label}
		if pids[i] == 0 {
			it.Status, it.Value = d.Missing, "未运行"
			it.Detail = d.Why
			it.Fix = "在设置里「重启服务」; 反复退出请导出诊断包"
			items = append(items, it)
			continue
		}
		s, _ := c.read(fmt.Sprintf("/proc/%d/stat", pids[i]))
		t2, _ := scParseProcStat(s)
		st, _ := c.read(fmt.Sprintf("/proc/%d/status", pids[i]))
		rss := scParseVmRSS(st)
		cpu := 0.0
		if t2 >= t1[i] {
			cpu = float64(t2-t1[i]) / userHZ / el * 100
		}
		it.Status = scOK
		it.Value = fmt.Sprintf("PID %d · 内存 %s · CPU %.1f%%", pids[i], scBytes(float64(rss)*1024), cpu)
		it.Detail = fmt.Sprintf("累计 CPU 时间 %.1f 秒", float64(t2)/userHZ)
		if cpu > 50 {
			it.Status = scWarn
			it.Detail += "; CPU 占用偏高"
		}
		if rss > 200*1024 {
			it.Status = scWarn
			it.Detail += "; 内存占用偏高"
		}
		items = append(items, it)
	}

	cnt := c.readTrim("/proc/sys/net/netfilter/nf_conntrack_count")
	max := c.readTrim("/proc/sys/net/netfilter/nf_conntrack_max")
	ct := scItem{ID: "conntrack_usage", Label: "连接表占用"}
	n, e1 := strconv.ParseFloat(cnt, 64)
	m, e2 := strconv.ParseFloat(max, 64)
	if e1 == nil && e2 == nil && m > 0 {
		ct.Status = scConntrackStatus(n, m)
		ct.Value = fmt.Sprintf("%s / %s(%.0f%%)", cnt, max, n/m*100)
		if ct.Status != scOK {
			ct.Detail = "连接表接近上限时新连接会被丢弃(表现为部分设备打不开网页)"
		}
	} else {
		ct.Status, ct.Value = scInfo, "不可读"
	}
	items = append(items, ct)

	mem := scItem{ID: "mem_available", Label: "可用内存", Status: scInfo}
	mi, _ := c.read("/proc/meminfo")
	for _, ln := range strings.Split(mi, "\n") {
		if strings.HasPrefix(ln, "MemAvailable:") {
			if f := strings.Fields(ln); len(f) >= 2 {
				kb, _ := strconv.ParseFloat(f[1], 64)
				mem.Value = scBytes(kb * 1024)
				mem.Status = scOK
				if kb < 200*1024 {
					mem.Status = scWarn
					mem.Detail = "可用内存过低, 系统可能杀掉 HNC 后台进程"
				}
			}
		}
	}
	if mem.Value == "" {
		mem.Value = "未知"
	}
	items = append(items, mem)
	if la := c.readTrim("/proc/loadavg"); la != "" {
		items = append(items, scItem{ID: "loadavg", Label: "系统负载", Status: scInfo, Value: strings.Join(strings.Fields(la)[:3], " ")})
	}
	items = append(items, scPowerItem(c)) // v5.22: 功耗汇总(power_stats.go)
	return items
}

// scConntrackStatus 连接表占用 → 状态(纯函数)
func scConntrackStatus(count, max float64) string {
	if max <= 0 {
		return scInfo
	}
	r := count / max
	switch {
	case r >= 0.9:
		return scFail
	case r >= 0.75:
		return scWarn
	}
	return scOK
}

// ═══ 识别 ═════════════════════════════════════════════════════════

// scUnknownRatio app_usage 一天的数据 → (未识别字节, 总字节)
func scUnknownRatio(d *appUsageDay) (float64, float64) {
	if d == nil {
		return 0, 0
	}
	var unk, tot float64
	for _, cells := range d.Hours {
		for mk, v := range cells {
			b := float64(v[0] + v[1])
			tot += b
			if i := strings.IndexByte(mk, '|'); i >= 0 && mk[i+1:] == appUnknownID {
				unk += b
			}
		}
	}
	return unk, tot
}

// scEncryptedDNSSuspects dpi_state.clients: TLS 事件不少但 DNS 为 0 的客户端(疑似 DoH/DoT)
func scEncryptedDNSSuspects(state map[string]interface{}) (suspects []string, clients int) {
	cl, _ := state["clients"].(map[string]interface{})
	for key, v := range cl {
		m, _ := v.(map[string]interface{})
		if m == nil {
			continue
		}
		clients++
		tls, _ := toInt64(m["tls_events"])
		dns, _ := toInt64(m["dns_events"])
		if tls >= 30 && dns*20 < tls { // DNS 不足 TLS 的 5%
			id := asString(m["client_mac"])
			if id == "" {
				id = asString(m["client_ip"])
			}
			if id == "" {
				id = key
			}
			suspects = append(suspects, id)
		}
	}
	sort.Strings(suspects)
	return
}

// scIPNameFreshWindow dpid 启动后多久内"没有映射文件"算正常(文件只在学到新映射后写, 每 10 秒一次)
const scIPNameFreshWindow = 10 * 60

// procUptime 进程已运行秒数(/proc/<pid>/stat starttime 与 /proc/uptime, USER_HZ=100)
func (c *scCtx) procUptime(pid int) (int64, bool) {
	if pid <= 0 {
		return 0, false
	}
	st := c.readTrim(fmt.Sprintf("/proc/%d/stat", pid))
	i := strings.LastIndexByte(st, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(st[i+1:])
	if len(f) < 20 {
		return 0, false
	}
	start, err := strconv.ParseInt(f[19], 10, 64) // 总第 22 字段
	if err != nil {
		return 0, false
	}
	uf := strings.Fields(c.readTrim("/proc/uptime"))
	if len(uf) == 0 {
		return 0, false
	}
	up, err := strconv.ParseFloat(uf[0], 64)
	if err != nil {
		return 0, false
	}
	secs := int64(up) - start/100
	if secs < 0 {
		return 0, false
	}
	return secs, true
}

// ipnameMissing v5.20.1: dpi_ipname.json 不存在时区分"还没学到"与"路径不对"。
// dpid 的 run 目录来自 etc/dpi_config.json 的 run_dir(缺省 /data/local/hnc/run),
// httpd(api_conn.go loadIPNames)与自检读 <HNC>/run/dpi_ipname.json。
func (c *scCtx) ipnameMissing(nit *scItem, pid int, st map[string]interface{}) {
	want := c.hnc("run")
	if cfg := c.readJSON(c.hnc("etc", "dpi_config.json")); cfg != nil {
		if rd := strings.TrimSpace(asString(cfg["run_dir"])); rd != "" && filepath.Clean(rd) != filepath.Clean(want) {
			nit.Status, nit.Value = scWarn, "文件路径异常"
			nit.Detail = "dpid 配置 run_dir=" + rd + ", 而界面/自检读 " + filepath.Join(want, "dpi_ipname.json")
			if c.env.Exists(filepath.Join(rd, "dpi_ipname.json")) {
				nit.Detail += "(dpid 写的文件在 " + filepath.Join(rd, "dpi_ipname.json") + ")"
			}
			nit.Fix = "删掉 etc/dpi_config.json 里的 run_dir(或改成 " + want + ")后重启服务"
			return
		}
	}
	if pid <= 0 {
		nit.Status, nit.Value = scInfo, "无(dpid 未运行)"
		return
	}
	events := int64(0)
	if stats, ok := st["stats"].(map[string]interface{}); ok {
		d, _ := toInt64(stats["dns_events"])
		t, _ := toInt64(stats["tls_events"])
		events = d + t
	}
	up, upOK := c.procUptime(pid)
	switch {
	case upOK && up < scIPNameFreshWindow:
		nit.Status, nit.Value = scInfo, "暂无(还没有设备产生 DNS/TLS 流量)"
		nit.Detail = fmt.Sprintf("dpid 已运行 %s; 学到第一条映射后 10 秒内写出 run/dpi_ipname.json", scDur(up))
	case events > 0:
		nit.Status, nit.Value = scWarn, "缺失"
		nit.Detail = fmt.Sprintf("dpid 已处理 %d 个 DNS/TLS 事件, 但没有写出 run/dpi_ipname.json(写入失败或权限问题?)", events)
		nit.Fix = "导出诊断包查看 logs/dpid.log; 或在设置里「重启服务」"
	default:
		nit.Status, nit.Value = scInfo, "暂无(还没有设备产生 DNS/TLS 流量)"
		if upOK {
			nit.Detail = fmt.Sprintf("dpid 已运行 %s, 尚未看到 DNS/TLS 事件", scDur(up))
		}
	}
}

func scSectionIdent(c *scCtx) []scItem {
	var items []scItem
	var dp scProcDef
	for _, d := range scProcDefs {
		if d.ID == "proc_dpid" {
			dp = d
		}
	}
	pid := c.findPID(dp)
	dit := scItem{ID: "dpid_running", Label: "识别引擎(dpid)"}
	if pid > 0 {
		dit.Status, dit.Value = scOK, fmt.Sprintf("运行中(PID %d)", pid)
	} else {
		dit.Status, dit.Value = scWarn, "未运行"
		dit.Fix = "在设置里「重启服务」"
	}
	items = append(items, dit)

	st := c.readJSON(c.hnc("run", "dpi_state.json"))
	sit := scItem{ID: "dpi_state", Label: "识别状态"}
	if st == nil {
		sit.Status, sit.Value = scWarn, "无状态文件"
	} else {
		ga, _ := toInt64(st["generated_at"])
		age := c.env.Now().Unix() - ga
		sit.Value = fmt.Sprintf("模式 %s · %s前更新", asString(st["mode"]), scDur(age))
		sit.Status = scOK
		var det []string
		if br := asString(st["blind_reason"]); br != "" {
			sit.Status = scWarn
			det = append(det, "盲区原因: "+br)
		}
		if age > 180 {
			sit.Status = scWarn
			det = append(det, "状态文件长时间未更新, dpid 可能卡住")
		}
		if v6, ok := st["ipv6_capture"].(bool); ok {
			det = append(det, "IPv6 抓包: "+scYesNo(v6))
		}
		if ifc := asString(st["interface"]); ifc != "" {
			det = append(det, "抓包接口: "+ifc)
		}
		sit.Detail = strings.Join(det, "; ")
	}
	items = append(items, sit)

	nit := scItem{ID: "ipname_entries", Label: "IP→域名映射"}
	if m := c.readJSON(c.hnc("run", "dpi_ipname.json")); m != nil {
		ents, _ := m["entries"].(map[string]interface{})
		nit.Value = fmt.Sprintf("%d 条", len(ents))
		nit.Status = scOK
		if len(ents) == 0 {
			nit.Status = scInfo
			nit.Detail = "尚未学到映射(还没有设备发起 DNS 查询)"
		}
	} else {
		c.ipnameMissing(&nit, pid, st)
	}
	items = append(items, nit)

	uit := scItem{ID: "unknown_ratio", Label: "今日未识别流量"}
	var day *appUsageDay
	if b, err := c.env.ReadFile(appUsagePath(c.env.HNCDir, c.env.Now().Format("20060102"))); err == nil {
		var d appUsageDay
		if json.Unmarshal(b, &d) == nil {
			day = &d
		}
	}
	unk, tot := scUnknownRatio(day)
	if tot <= 0 {
		uit.Status, uit.Value = scInfo, "今日暂无流量记录"
	} else {
		r := unk / tot * 100
		uit.Value = fmt.Sprintf("%.0f%%(%s / %s)", r, scBytes(unk), scBytes(tot))
		uit.Status = scOK
		if r >= 60 {
			uit.Status = scWarn
			uit.Detail = "大部分流量未归到应用: 可能是加密 DNS/QUIC/VPN, 或规则库过旧"
			uit.Fix = "在「未识别流量」里教规则, 或更新规则库"
		}
	}
	items = append(items, uit)

	pit := scItem{ID: "private_dns", Label: "本机私人 DNS", Status: scInfo}
	mode, _ := c.run("settings", "get", "global", "private_dns_mode")
	mode = strings.TrimSpace(mode)
	switch mode {
	case "off":
		pit.Value = "关闭"
	case "opportunistic", "", "null":
		pit.Value = "自动"
	case "hostname":
		spec, _ := c.run("settings", "get", "global", "private_dns_specifier")
		pit.Value = "指定: " + strings.TrimSpace(spec)
		pit.Detail = "只影响本机自身流量(自抓包识别); 热点客户端不受影响"
	default:
		pit.Value = mode
	}
	items = append(items, pit)

	eit := scItem{ID: "encrypted_dns", Label: "加密 DNS 迹象"}
	if st == nil {
		eit.Status, eit.Value = scInfo, "无数据"
	} else {
		sus, n := scEncryptedDNSSuspects(st)
		stats, _ := st["stats"].(map[string]interface{})
		dns, _ := toInt64(stats["dns_events"])
		tls, _ := toInt64(stats["tls_events"])
		if tls > 0 {
			eit.Detail = fmt.Sprintf("全局 DNS/TLS 事件比 %d/%d", dns, tls)
		}
		switch {
		case n == 0:
			eit.Status, eit.Value = scInfo, "暂无客户端数据"
		case len(sus) == 0:
			eit.Status, eit.Value = scOK, "未发现"
		default:
			eit.Status = scWarn
			eit.Value = fmt.Sprintf("%d/%d 台设备可能在用加密 DNS", len(sus), n)
			eit.Detail = strings.TrimSpace("这些设备有大量 TLS 连接却几乎没有明文 DNS(DoH/DoT/私人 DNS), 域名识别只能靠 SNI: " +
				strings.Join(sus, " ") + "; " + eit.Detail)
			eit.Fix = "可在「设置」开启 DoT/DoH 拦截(若有), 或在客户端关闭私人 DNS"
		}
	}
	items = append(items, eit)
	return items
}

// ─── 真实环境 ────────────────────────────────────────────────────

func realSelfcheckEnv(hncDir string) *scEnv {
	return &scEnv{
		HNCDir:       hncDir,
		Version:      version,
		SelfPID:      os.Getpid(),
		LoopbackPort: *flagLoopbackPort,
		CmdTimeout:   selfcheckCmdTimeout,
		Budget:       selfcheckBudget,
		Run:          scRealRunner(hncDir),
		ReadFile: func(p string) ([]byte, error) {
			f, err := os.Open(p)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(bufio.NewReader(f), 16<<20))
		},
		ReadDir: func(p string) ([]string, error) {
			ents, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(ents))
			for _, e := range ents {
				out = append(out, e.Name())
			}
			return out, nil
		},
		Exists: func(p string) bool { _, err := os.Lstat(p); return err == nil },
		Getenv: os.Getenv,
		Now:    time.Now,
		Sleep: func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		},
		CtEvents: func() (bool, string) {
			ctEvents.mu.Lock()
			defer ctEvents.mu.Unlock()
			return ctEvents.active, ctEvents.lastErr
		},
	}
}

// scRealRunner 命令先按绝对路径找(运行期 /system/bin 可能被卸, 退 /data 副本), 再退 PATH。
func scRealRunner(hncDir string) func(ctx context.Context, name string, args ...string) (string, error) {
	dirs := []string{"/system/bin/", "/system/xbin/", "/vendor/bin/", hncDir + "/bin/",
		"/data/adb/ksu/bin/", "/data/adb/magisk/", "/data/adb/ap/bin/"}
	return func(ctx context.Context, name string, args ...string) (string, error) {
		path := name
		if !strings.HasPrefix(name, "/") {
			path = ""
			for _, d := range dirs {
				if st, err := os.Stat(d + name); err == nil && !st.IsDir() {
					path = d + name
					break
				}
			}
			if path == "" {
				p, err := exec.LookPath(name)
				if err != nil {
					return "", err
				}
				path = p
			}
		}
		cmd := hardenCmd(exec.CommandContext(ctx, path, args...))
		cmd.Env = []string{
			"HNC_DIR=" + hncDir, "HNC=" + hncDir,
			"PATH=/system/bin:/system/xbin:/vendor/bin:" + hncDir + "/bin:/data/adb/ksu/bin:/data/adb/magisk",
		}
		var out bytes.Buffer
		cmd.Stdout = &scLimitWriter{w: &out, n: 4 << 20}
		err := cmd.Run()
		if ctx.Err() != nil {
			return out.String(), ctx.Err()
		}
		return out.String(), err
	}
}

// scLimitWriter 截断超长输出(dumpsys 在个别 ROM 上可达数 MB)
type scLimitWriter struct {
	w io.Writer
	n int
}

func (l *scLimitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, _ = l.w.Write(q)
	return len(p), nil
}
