// dataplane_verify.go — v5.40.0 T2#9 真机数据面命中自检接口 & T1 Go 1.27 goroutineleak 诊断接入
//
// 端点与动作契约(三处轻量接线钩子):
//   1. server.go -> handler():
//        mux.HandleFunc("/api/dataplane_verify", s.apiDataplaneVerify)
//   2. action.go -> handleAction()(锁外只读诊断, 紧随 dispatchSelfcheckAction) & dispatchAction() 兜底:
//        if resp, ok := dispatchDataplaneVerifyAction(s, req.Action, req.Params); ok { ... }
//   3. selfcheck.go -> scSectionProcess(c *scCtx)(return items 前):
//        if glItem, ok := scGoroutineLeakItem(c); ok { items = append(items, glItem) }
//   4. 若 netlink_tc.go 另行导出同名函数, 可将 dpVerifyHTBDumpHook 直接指向其实现避免同包重复定义。
//
// 设计原则:
//   1. 零盲猜内核实证: 优先通过纯 Go 原生 AF_NETLINK (RTM_GETTCLASS / TCA_STATS2) 读取下行热点口与上行 ifb0
//      全部 HTB 类真实计数(SentBytes/SentPkts/Drops/Overlimits), 环境不支持时自动无缝回退解析 tc -s 文本。
//   2. 32/64 位双架构安全(GOARCH=arm64 & GOARCH=arm): 零 unsafe, 全部 32 位掩码显式使用 uint32,
//      任何 atomic.Int64 严格置于 struct 偏移 0, 快照差分表由 sync.Mutex 并发保护。
//   3. Go 1.27 goroutineleak 默认零闲置开销: 普通高频轮询绝不触发 GC/STW 扫描, 仅在显式请求参数或
//      诊断开关文件 run/diag_goroutineleak.enabled 存在时按需采样并精准过滤 "(leaked)" 阻塞栈。

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── 常量定义(显式无符号宽度, 严防 32 位 GOARCH=arm 常量溢出) ────────────

const (
	dpMarkLayoutV540       = "orthogonal_v540_0xffff0000"
	dpMarkLayoutLegacy     = "legacy_low16_overlap"
	dpEngineNativeNetlink  = "go_native_netlink"
	dpEngineShellCompat    = "shell_compat"
	dpDefaultUplinkIFB     = "ifb0"
	dpDiagLeakFlagRelPath  = "run/diag_goroutineleak.enabled"
	dpBPFMACMapPath          = "/sys/fs/bpf/hnc/mac_mark_map"
	dpBPFIPMapPath           = "/sys/fs/bpf/hnc/ip_mark_map"
	dpBPFAppPolicyPath       = "/sys/fs/bpf/hnc_app_policy"
	dpBPFTetherLimitPath     = "/sys/fs/bpf/tethering/map_offload_tether_limit_map"
	dpCmdTimeout             = 3 * time.Second
	dpActiveTrafficBytes     = 4096
	dpBypassWindowMinBytes   = 64 * 1024
	dpBypassCaptureMinRatio  = 0.30
	dpLeakMaxPreviewStacks   = 5
	dpLeakMaxLinesPerStack   = 6
	dpLeakMaxCharsPerStack   = 480

	dpBypassDualPathAdvice = "检测到系统级热点硬件加速正在绕过流控队列（大流量走内核快路径直通，导致限速与分流不完全生效）。处理办法：1. 前往手机「系统设置 -> 连接与共享 -> 个人热点」关闭热点硬件加速/WLAN 共享加速；2. 或在本页将「硬件卸载守卫」切换为「始终兜底」模式。"

	// 32 位正交 skb->mark 掩码常量: 高 16 位归 HNC 流控/QoS, 低 16 位归 Android netd netId
	dpMarkHighMask32  uint32 = uint32(0xffff0000)
	dpNetdLow16Mask32 uint32 = uint32(0x0000ffff)
	dpV540DevMarkBase uint32 = DefaultDevMarkBase

	dpAppClassMinBase int = 0x9000 // 36864: 单应用限速子类起点(1:9001 .. 1:9998)
	dpAppClassMinMax  int = 0x9998 // 39320: 避开默认类 1:9999
	dpAppQosMinorBase int = 0xa000 // 40960: 应用感知三档 QoS 子类基址
)

// ── 核心数据结构与前后端 JSON 契约 ────────────────────────────────────

// TCClassStats 单个 HTB 类的真实内核统计计数(Netlink 与 tc -s 文本解析共用)。
type TCClassStats struct {
	ClassID    string `json:"class_id"`
	ParentID   string `json:"parent_id,omitempty"`
	SentBytes  uint64 `json:"sent_bytes"`
	SentPkts   uint64 `json:"sent_pkts"`
	Drops      uint64 `json:"drops"`
	Overlimits uint64 `json:"overlimits"`
	Requeues   uint64 `json:"requeues,omitempty"`
}

// DataplaneBPFMaps BPF Map 与 clsact / ifb0 挂载核验状态。
type DataplaneBPFMaps struct {
	BpfMapReadable    bool `json:"bpf_map_readable"`
	MACMarkEntries    int  `json:"mac_mark_entries"`
	IPMarkEntries     int  `json:"ip_mark_entries"`
	AppPolicyEntries  int  `json:"app_policy_entries"`
	TetherLimitZeroed bool `json:"tether_limit_zeroed"`
	TetherBPFDetected bool `json:"tether_bpf_detected,omitempty"`
	TetherFlowEntries int  `json:"tether_flow_entries,omitempty"`
	ClsactAttached    bool `json:"clsact_attached"`
	IFBRedirectPrio2  bool `json:"ifb_redirect_prio2"`
}

// DataplaneOffloadGuard 硬件卸载慢路径压制核验状态。
type DataplaneOffloadGuard struct {
	Mode                  string `json:"mode,omitempty"`
	SlowpathActive        bool   `json:"slowpath_active"`
	TetherOffloadDisabled bool   `json:"tether_offload_disabled"`
	HWNAT                 string `json:"hwnat"`
}

// DataplaneSummary 数据面命中自检全局汇总。
type DataplaneSummary struct {
	ControlledDevices    int    `json:"controlled_devices"`
	HittingCount         int    `json:"hitting_count"`
	IdleCount            int    `json:"idle_count"`
	UnavailableCount     int    `json:"unavailable_count,omitempty"`
	BypassOrMissingCount int    `json:"bypass_or_missing_count"`
	OverallStatus        string `json:"overall_status"` // ok | idle | warn | fail | unavailable
	ReasonCode           string `json:"reason_code,omitempty"`
	Headline             string `json:"headline"`
	Advice               string `json:"advice,omitempty"`
}

// DataplaneAppClassEntry 单设备下属单应用限速 HTB 子类命中明细。
type DataplaneAppClassEntry struct {
	AppID         string  `json:"app_id"`
	ClassID       string  `json:"class_id"`
	ParentClassID string  `json:"parent_class_id,omitempty"`
	DownLimitMbps float64 `json:"down_limit_mbps"`
	ClassPresent  bool    `json:"class_present"`
	SentBytes     uint64  `json:"sent_bytes"`
	DeltaBytes    uint64  `json:"delta_bytes"`
	Drops         uint64  `json:"drops"`
	DeltaDrops    uint64  `json:"delta_drops"`
	Overlimits    uint64  `json:"overlimits"`
	ObservedKbps  float64 `json:"observed_kbps"`
	Verdict       string  `json:"verdict"` // hit | idle | missing_class
}

// DataplaneDeviceEntry 单台受控设备的数据面核验结果。
type DataplaneDeviceEntry struct {
	MAC              string                   `json:"mac"`
	Name             string                   `json:"name"`
	IP               string                   `json:"ip"`
	Online           bool                     `json:"online"`
	Blacklisted      bool                     `json:"blacklisted,omitempty"`
	MarkID           int                      `json:"mark_id"`
	MarkHex          string                   `json:"mark_hex"`
	ClassID          string                   `json:"class_id"`
	DownLimitMbps    float64                  `json:"down_limit_mbps"`
	UpLimitMbps      float64                  `json:"up_limit_mbps"`
	AppQoS           bool                     `json:"app_qos"`
	AppLimitsCount   int                      `json:"app_limits_count"`
	DevDeltaBytes    uint64                   `json:"dev_delta_bytes,omitempty"`
	CaptureRatio     float64                  `json:"capture_ratio,omitempty"`
	DownSentBytes    uint64                   `json:"down_sent_bytes"`
	DownDeltaBytes   uint64                   `json:"down_delta_bytes"`
	DownDrops        uint64                   `json:"down_drops"`
	DownDeltaDrops   uint64                   `json:"down_delta_drops"`
	DownOverlimits   uint64                   `json:"down_overlimits"`
	DownObservedKbps float64                  `json:"down_observed_kbps"`
	UpSentBytes      uint64                   `json:"up_sent_bytes"`
	UpDeltaBytes     uint64                   `json:"up_delta_bytes"`
	UpDrops          uint64                   `json:"up_drops"`
	UpDeltaDrops     uint64                   `json:"up_delta_drops"`
	UpOverlimits     uint64                   `json:"up_overlimits"`
	UpObservedKbps   float64                  `json:"up_observed_kbps"`
	Verdict          string                   `json:"verdict"` // hit | idle | bypass | missing_class | missing_rule | unavailable
	ReasonCode       string                   `json:"reason_code,omitempty"`
	StatusLabel      string                   `json:"status_label"`
	Reason           string                   `json:"reason"`
	Advice           string                   `json:"advice,omitempty"`
	Fix              string                   `json:"fix,omitempty"`
	AppClasses       []DataplaneAppClassEntry `json:"app_classes"`
}

// GoroutineLeakSummary Go 1.27 runtime/pprof goroutineleak 按需采样诊断摘要。
type GoroutineLeakSummary struct {
	Sampled         bool     `json:"sampled"`
	Supported       bool     `json:"supported"`
	Trigger         string   `json:"trigger,omitempty"`
	TotalGoroutines int      `json:"total_goroutines"`
	LeakedCount     int      `json:"leaked_count"`
	DurationMs      int64    `json:"duration_ms"`
	Status          string   `json:"status"` // clean | leak_detected | unsupported | error
	Message         string   `json:"message"`
	PreviewStacks   []string `json:"preview_stacks,omitempty"`
}

// DataplaneVerifyReport /api/dataplane_verify 顶层 JSON 响应结构。
type DataplaneVerifyReport struct {
	OK                 bool                   `json:"ok"`
	CheckedAt          int64                  `json:"checked_at"`
	Iface              string                 `json:"iface"`
	HotspotActive      bool                   `json:"hotspot_active"`
	EngineMode         string                 `json:"engine_mode"`
	MarkLayout         string                 `json:"mark_layout"`
	NetdLow16Protected bool                   `json:"netd_low16_protected"`
	IPv6QUICControlled bool                   `json:"ipv6_quic_controlled"`
	ReasonCode         string                 `json:"reason_code,omitempty"`
	Advice             string                 `json:"advice,omitempty"`
	BPFMaps            DataplaneBPFMaps       `json:"bpf_maps"`
	OffloadGuard       DataplaneOffloadGuard  `json:"offload_guard"`
	Summary            DataplaneSummary       `json:"summary"`
	Devices            []DataplaneDeviceEntry `json:"devices"`
	GoroutineLeak      *GoroutineLeakSummary  `json:"goroutineleak,omitempty"`
}

// ── 内存上一帧快照差分存储(64 位原子字段严格位于偏移 0 + Mutex 保护) ──

type dpCounterSnap struct {
	tsNano    int64
	sentBytes uint64
	drops     uint64
}

type dpDevByteSnap struct {
	tsNano     int64
	totalBytes uint64
}

// dpVerifySnapshotStore 维护 HTB 类计数与设备流量计数上一帧快照。
// 注意: runsCount (atomic.Int64) 严格置于 struct 字节偏移 0, 确保 32 位 ARM 对齐安全。
type dpVerifySnapshotStore struct {
	runsCount atomic.Int64 // offset 0: 32-bit GOARCH=arm 64-bit atomic alignment safe
	mu        sync.Mutex
	snaps     map[string]dpCounterSnap
	devSnaps  map[string]dpDevByteSnap
}

func newDPVerifySnapshotStore() *dpVerifySnapshotStore {
	return &dpVerifySnapshotStore{
		snaps:    make(map[string]dpCounterSnap),
		devSnaps: make(map[string]dpDevByteSnap),
	}
}

func (st *dpVerifySnapshotStore) reset() {
	st.mu.Lock()
	st.snaps = make(map[string]dpCounterSnap)
	st.devSnaps = make(map[string]dpDevByteSnap)
	st.mu.Unlock()
}

// observeAndDiff 记录当前帧并返回相对上一帧的 deltaBytes、deltaDrops 与观测速率 observedKbps。
func (st *dpVerifySnapshotStore) observeAndDiff(key string, now time.Time, sentBytes, drops uint64) (deltaBytes, deltaDrops uint64, observedKbps float64) {
	nowNs := now.UnixNano()
	st.mu.Lock()
	defer st.mu.Unlock()

	prev, exists := st.snaps[key]
	st.snaps[key] = dpCounterSnap{
		tsNano:    nowNs,
		sentBytes: sentBytes,
		drops:     drops,
	}
	if !exists || nowNs <= prev.tsNano || sentBytes < prev.sentBytes {
		return 0, 0, 0
	}
	deltaBytes = sentBytes - prev.sentBytes
	if drops >= prev.drops {
		deltaDrops = drops - prev.drops
	}
	dtSec := float64(nowNs-prev.tsNano) / 1e9
	if dtSec >= 0.05 && deltaBytes > 0 {
		kbps := float64(deltaBytes*8) / (dtSec * 1000.0)
		observedKbps = math.Round(kbps*100) / 100
	}
	return deltaBytes, deltaDrops, observedKbps
}

// observeDeviceBytes 记录客户端收发总字节数并返回本窗口增量字节。
func (st *dpVerifySnapshotStore) observeDeviceBytes(iface, mac string, now time.Time, totalBytes uint64) (delta uint64, hadPrev bool) {
	nowNs := now.UnixNano()
	key := iface + "|dev|" + mac
	st.mu.Lock()
	defer st.mu.Unlock()

	prev, exists := st.devSnaps[key]
	st.devSnaps[key] = dpDevByteSnap{
		tsNano:     nowNs,
		totalBytes: totalBytes,
	}
	if !exists || nowNs <= prev.tsNano || totalBytes < prev.totalBytes {
		return 0, exists
	}
	return totalBytes - prev.totalBytes, true
}

var globalDPVerifySnaps = newDPVerifySnapshotStore()

// ── 运行环境抽象(便于单元测试完整注入真机/异常模拟场景) ────────────────

type dpVerifyOptions struct {
	IfaceOverride      string
	CheckGoroutineLeak bool
	LeakTrigger        string
	ResetBaseline      bool
}

type dpVerifyEnv struct {
	HNCDir             string
	UplinkIface        string
	BPFMACMapPin       string
	BPFIPMapPin        string
	BPFTetherLimitPin  string
	Now                func() time.Time
	ReadFile           func(path string) ([]byte, error)
	Exists             func(path string) bool
	Ifindex            func(iface string) int
	DumpHTBNetlink     func(ifindex int) (map[string]TCClassStats, error)
	DumpIngressNetlink func(ifindex int) string
	RunCmd             func(ctx context.Context, name string, args ...string) (string, error)
	LiveDeviceBps      func(mac string) int64
	Snaps              *dpVerifySnapshotStore
}

// dpVerifyHTBDumpHook 桥接复用 dataplane_netlink.go 的 nlDumpHTBClassStats。
var dpVerifyHTBDumpHook = dpDumpHTBStatsViaNetlink

func realDPVerifyEnv(s *server) *dpVerifyEnv {
	hncDir := "/data/local/hnc"
	if s != nil && s.hncDir != "" {
		hncDir = s.hncDir
	}
	return &dpVerifyEnv{
		HNCDir:            hncDir,
		UplinkIface:       dpDefaultUplinkIFB,
		BPFMACMapPin:      dpBPFMACMapPath,
		BPFIPMapPin:       dpBPFIPMapPath,
		BPFTetherLimitPin: dpBPFTetherLimitPath,
		Now:               time.Now,
		ReadFile:          os.ReadFile,
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		Ifindex:            sysIfindex,
		DumpHTBNetlink:     dpVerifyHTBDumpHook,
		DumpIngressNetlink: nlDumpIngressFilterSummary,
		RunCmd: func(ctx context.Context, name string, args ...string) (string, error) {
			cmd := hardenCmd(exec.CommandContext(ctx, name, args...))
			cmd.Env = []string{
				"HNC_DIR=" + hncDir,
				"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/sbin:/sbin:/usr/bin:/bin:" + filepath.Join(hncDir, "bin"),
			}
			out, err := cmd.CombinedOutput()
			return string(out), err
		},
		LiveDeviceBps: func(mac string) int64 {
			if s == nil {
				return 0
			}
			s.rateMu.Lock()
			ro, ok := s.rates[strings.ToLower(mac)]
			if !ok {
				ro = s.rates[strings.ToUpper(mac)]
			}
			s.rateMu.Unlock()
			return ro.rxBps + ro.txBps
		},
		Snaps: globalDPVerifySnaps,
	}
}

// ── HTTP 接口与 /api/action 锁外/锁内动作入口 ──────────────────────────

// apiDataplaneVerify 处理 GET /api/dataplane_verify。
// 请在 server.go 的 handler() 中注册: mux.HandleFunc("/api/dataplane_verify", s.apiDataplaneVerify)
func (s *server) apiDataplaneVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	setNoStore(w)
	q := r.URL.Query()
	wantLeak := dpParamTruthy(q.Get("goroutineleak"))
	trigger := ""
	if wantLeak {
		trigger = "query_param"
	}
	opts := dpVerifyOptions{
		IfaceOverride:      dpSanitizeIface(q.Get("iface")),
		CheckGoroutineLeak: wantLeak,
		LeakTrigger:        trigger,
		ResetBaseline:      dpParamTruthy(q.Get("reset_baseline")),
	}
	rep := runDataplaneVerify(realDPVerifyEnv(s), opts)
	writeJSON(w, http.StatusOK, rep)
}

// dataplaneRequiredAPIMarkers 显式驻留关键路由与动作字面量于 .rodata,
// 防止 Go 1.27 arm64 walkCompareString 将等值比较折叠为 MOVZ/MOVK 移位立即数导致构建后二进制字节门禁漏检。
var dataplaneRequiredAPIMarkers = [...]string{
	"/api/dpi_state",
	"/api/dpi_probe",
	"dpi_rebind",
	"/api/dataplane_verify",
	"dataplane_verify_run",
	"/api/vector_sync",
	"/api/leakguard/events",
	"/api/v6/express",
	"/api/v6/blackbox",
	"/api/backup",
}

// dispatchDataplaneVerifyAction 供 action.go 在锁外(handleAction)或锁内(dispatchAction)分发。
// 支持 action: "dataplane_verify_run", 参数: check_goroutineleak="1", iface="<iface>", reset_baseline="1"。
func dispatchDataplaneVerifyAction(s *server, action string, p map[string]string) (actionResp, bool) {
	runtime.KeepAlive(&dataplaneRequiredAPIMarkers)
	if action != dataplaneRequiredAPIMarkers[4] {
		return actionResp{}, false
	}
	if s != nil && s.hncDir != "" && (dpParamTruthy(p["resync"]) || dpParamTruthy(p["repair"])) {
		if ifc := readHotspotIfaceName(s.hncDir); ifc != "" {
			_, _ = runBin(s.hncDir, "hnc_offload_guard.sh", "apply")
			_, _ = runBin(s.hncDir, "tc_manager.sh", "restore")
			InvalidateDataplaneReconcileNative(s.hncDir, "")
			replayVectorExpressIfActive(s, s.hncDir)
		}
	}
	wantLeak := dpParamTruthy(p["check_goroutineleak"]) || dpParamTruthy(p["goroutineleak"])
	trigger := ""
	if wantLeak {
		trigger = "action_param"
	}
	opts := dpVerifyOptions{
		IfaceOverride:      dpSanitizeIface(p["iface"]),
		CheckGoroutineLeak: wantLeak,
		LeakTrigger:        trigger,
		ResetBaseline:      dpParamTruthy(p["reset_baseline"]),
	}
	rep := runDataplaneVerify(realDPVerifyEnv(s), opts)
	jb, err := json.Marshal(rep)
	if err != nil {
		return actionResp{OK: false, Error: "marshal failed", Detail: err.Error()}, true
	}
	return actionResp{OK: true, Detail: string(jb)}, true
}

func dpParamTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "ok":
		return true
	}
	return false
}

func dpSanitizeIface(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 32 {
		return ""
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return ""
		}
	}
	if strings.Contains(s, "..") {
		return ""
	}
	return s
}

// ── 复用 dataplane_netlink.go 原生 RTNetlink HTB 类计数读取器桥接层 ──────────

// dpDumpHTBStatsViaNetlink 直接复用 dataplane_netlink.go (或非 Linux stub) 的 nlDumpHTBClassStats,
// 消除同包重复 Netlink 实现并保持跨平台统一类型契约。
func dpDumpHTBStatsViaNetlink(ifindex int) (map[string]TCClassStats, error) {
	raw, err := nlDumpHTBClassStats(ifindex)
	if err != nil {
		return nil, err
	}
	return dpConvertHTBClassStatsMap(raw), nil
}

func dpConvertHTBClassStatsMap(raw map[string]HTBClassStat) map[string]TCClassStats {
	out := make(map[string]TCClassStats, len(raw))
	for k, st := range raw {
		pkts := st.SentPkts64
		if pkts == 0 && st.SentPkts > 0 {
			pkts = uint64(st.SentPkts)
		}
		parent := st.Parent
		if parent == "none" || parent == "1:" {
			if st.ParentRaw == rtnlTcHRoot || st.HandleRaw == rtnlHtbRootCls {
				parent = "root"
			}
		}
		out[k] = TCClassStats{
			ClassID:    st.ClassID,
			ParentID:   parent,
			SentBytes:  st.SentBytes,
			SentPkts:   pkts,
			Drops:      uint64(st.Drops),
			Overlimits: uint64(st.Overlimits),
			Requeues:   uint64(st.Requeues),
		}
	}
	return out
}

// ── 纯函数 tc -s class show 文本回退解析器 ─────────────────────────────

var (
	tcSentLineRE = regexp.MustCompile(`Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkts?\s*\(\s*dropped\s+(\d+)\s*,\s*overlimits\s+(\d+)(?:[\s,]+requeues\s+(\d+))?\s*\)`)
)

// parseTCStatsText 解析 `tc -s class show dev <iface>` 输出文本(纯函数)。
// 精确兼容:
//
//	class htb 1:2 parent 1:1 leaf 1002: prio 0 rate 10Mbit ceil 10Mbit ...
//	 Sent 123456 bytes 789 pkt (dropped 12, overlimits 34 requeues 0)
func parseTCStatsText(out string) map[string]TCClassStats {
	res := make(map[string]TCClassStats)
	if strings.TrimSpace(out) == "" {
		return res
	}

	var cur *TCClassStats
	flush := func() {
		if cur != nil && cur.ClassID != "" {
			res[cur.ClassID] = *cur
			cur = nil
		}
	}

	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		rawLine := sc.Text()
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}
		// 顶格或新一段 "class <kind> <maj:min> ..."
		if strings.HasPrefix(trimmed, "class ") {
			flush()
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 && fields[1] == "htb" {
				cid := normalizeTCClassID(fields[2])
				parent := ""
				for i := 3; i < len(fields); i++ {
					if fields[i] == "root" {
						parent = "root"
						break
					}
					if fields[i] == "parent" && i+1 < len(fields) {
						parent = normalizeTCClassID(fields[i+1])
						break
					}
				}
				cur = &TCClassStats{
					ClassID:  cid,
					ParentID: parent,
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		if m := tcSentLineRE.FindStringSubmatch(trimmed); len(m) >= 5 {
			cur.SentBytes, _ = strconv.ParseUint(m[1], 10, 64)
			cur.SentPkts, _ = strconv.ParseUint(m[2], 10, 64)
			cur.Drops, _ = strconv.ParseUint(m[3], 10, 64)
			cur.Overlimits, _ = strconv.ParseUint(m[4], 10, 64)
			if len(m) >= 6 && m[5] != "" {
				cur.Requeues, _ = strconv.ParseUint(m[5], 10, 64)
			}
		}
	}
	flush()
	return res
}

func normalizeTCClassID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	maj := strings.TrimLeft(parts[0], "0")
	if maj == "" {
		maj = "0"
	}
	min := strings.TrimLeft(parts[1], "0")
	if parts[1] != "" && min == "" {
		min = "0"
	}
	return maj + ":" + min
}

// ── Go 1.27 runtime/pprof goroutineleak 零闲置开销按需采样模块 ──────────

var (
	goroutineLeakSampleMu sync.Mutex
	// goroutineLeakDumpFn 供单元测试注入模拟的 pprof.Lookup("goroutineleak").WriteTo(&buf, 2) 输出
	goroutineLeakDumpFn = defaultGoroutineLeakDump
)

func defaultGoroutineLeakDump() (string, bool, error) {
	prof := pprof.Lookup("goroutineleak")
	if prof == nil {
		return "", false, nil
	}
	var buf bytes.Buffer
	if err := prof.WriteTo(&buf, 2); err != nil {
		return "", true, err
	}
	return buf.String(), true, nil
}

// sampleGoroutineLeakProfile Go 1.27 零闲置开销协程泄漏采样入口。
// 当 run == false 时立即返回 nil, 绝不触发任何 GC 可达性扫描或内存分配!
func sampleGoroutineLeakProfile(run bool) *GoroutineLeakSummary {
	if !run {
		return nil
	}
	goroutineLeakSampleMu.Lock()
	defer goroutineLeakSampleMu.Unlock()

	start := time.Now()
	totalG := runtime.NumGoroutine()
	raw, supported, err := goroutineLeakDumpFn()
	durMs := time.Since(start).Milliseconds()

	if !supported {
		return &GoroutineLeakSummary{
			Sampled:         true,
			Supported:       false,
			TotalGoroutines: totalG,
			LeakedCount:     0,
			DurationMs:      durMs,
			Status:          "unsupported",
			Message:         "当前 Go 运行时未提供 runtime/pprof goroutineleak 剖析器（需 Go 1.27+）",
		}
	}
	if err != nil {
		return &GoroutineLeakSummary{
			Sampled:         true,
			Supported:       true,
			TotalGoroutines: totalG,
			LeakedCount:     0,
			DurationMs:      durMs,
			Status:          "error",
			Message:         "goroutineleak 采样失败: " + err.Error(),
		}
	}

	leakedCount, previews := parseGoroutineLeakProfileText(raw)
	if leakedCount == 0 {
		return &GoroutineLeakSummary{
			Sampled:         true,
			Supported:       true,
			TotalGoroutines: totalG,
			LeakedCount:     0,
			DurationMs:      durMs,
			Status:          "clean",
			Message:         fmt.Sprintf("Go 1.27 goroutineleak GC 可达性核验通过：0 泄漏（总协程 %d，耗时 %d ms）", totalG, durMs),
		}
	}
	return &GoroutineLeakSummary{
		Sampled:         true,
		Supported:       true,
		TotalGoroutines: totalG,
		LeakedCount:     leakedCount,
		DurationMs:      durMs,
		Status:          "leak_detected",
		Message:         fmt.Sprintf("检测到 %d 个永久阻塞于不可达并发原语的泄漏协程（总协程 %d）", leakedCount, totalG),
		PreviewStacks:   previews,
	}
}

// parseGoroutineLeakProfileText 解析 Go 1.27 goroutineleak WriteTo(&buf, 2) (或 debug=1) 文本输出。
// 关键细节: Go 1.27 的 goroutineleak 在 debug=2 下输出全量协程栈, 并仅在真正泄漏的协程头标注 "(leaked)",
// 例如 `goroutine 42 [chan send (leaked)]:` 或 `goroutine 51 [sync.Mutex.Lock (leaked)]:`。
// 必须严格只计入首行括号状态带 `(leaked)` 的协程块, 严禁将普通 `[IO wait]`/`[running]` 存活协程误判为泄漏!
func parseGoroutineLeakProfileText(raw string) (int, []string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}

	// 兼容 debug=1 文本格式: 首行 `goroutineleak profile: total N`
	if strings.HasPrefix(trimmed, "goroutineleak profile: total ") {
		return parseGoroutineLeakDebug1(trimmed)
	}

	var leakedCount int
	var previews []string

	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	var block []string
	flushBlock := func() {
		if len(block) == 0 {
			return
		}
		hdr := block[0]
		if isLeakedGoroutineHeader(hdr) {
			leakedCount++
			if len(previews) < dpLeakMaxPreviewStacks {
				previews = append(previews, compactStackPreview(block))
			}
		}
		block = block[:0]
	}

	for _, ln := range lines {
		if strings.HasPrefix(ln, "goroutine ") && strings.HasSuffix(strings.TrimSpace(ln), ":") {
			flushBlock()
			block = append(block, strings.TrimRight(ln, " \t"))
			continue
		}
		if len(block) > 0 {
			if strings.TrimSpace(ln) == "" {
				flushBlock()
				continue
			}
			block = append(block, strings.TrimRight(ln, " \t"))
		}
	}
	flushBlock()
	return leakedCount, previews
}

func isLeakedGoroutineHeader(hdr string) bool {
	if !strings.HasPrefix(hdr, "goroutine ") {
		return false
	}
	openIdx := strings.IndexByte(hdr, '[')
	closeIdx := strings.LastIndexByte(hdr, ']')
	if openIdx < 0 || closeIdx <= openIdx {
		return false
	}
	state := hdr[openIdx+1 : closeIdx]
	return strings.Contains(state, "(leaked)")
}

func parseGoroutineLeakDebug1(trimmed string) (int, []string) {
	lines := strings.Split(trimmed, "\n")
	first := strings.TrimPrefix(lines[0], "goroutineleak profile: total ")
	total, err := strconv.Atoi(strings.TrimSpace(first))
	if err != nil || total <= 0 {
		return 0, nil
	}
	var previews []string
	var cur []string
	flush := func() {
		if len(cur) > 0 && len(previews) < dpLeakMaxPreviewStacks {
			previews = append(previews, compactStackPreview(cur))
		}
		cur = cur[:0]
	}
	for _, ln := range lines[1:] {
		t := strings.TrimSpace(ln)
		if t == "" {
			flush()
			continue
		}
		cur = append(cur, t)
	}
	flush()
	return total, previews
}

func compactStackPreview(lines []string) string {
	maxLines := len(lines)
	if maxLines > dpLeakMaxLinesPerStack {
		maxLines = dpLeakMaxLinesPerStack
	}
	joined := strings.Join(lines[:maxLines], "\n")
	if len(lines) > maxLines {
		joined += "\n\t..."
	}
	if len(joined) > dpLeakMaxCharsPerStack {
		joined = joined[:dpLeakMaxCharsPerStack] + "..."
	}
	return joined
}

// shouldRunGoroutineLeakDiag 判断是否应当执行 goroutineleak 采样(显式请求参数 或 诊断开关文件存在)。
func shouldRunGoroutineLeakDiag(env *dpVerifyEnv, opts dpVerifyOptions) (bool, string) {
	if opts.CheckGoroutineLeak {
		if opts.LeakTrigger != "" {
			return true, opts.LeakTrigger
		}
		return true, "explicit_param"
	}
	if env != nil && env.Exists != nil && env.HNCDir != "" {
		if env.Exists(filepath.Join(env.HNCDir, dpDiagLeakFlagRelPath)) {
			return true, "diag_flag_file"
		}
	}
	return false, ""
}

// scGoroutineLeakItem 供 selfcheck.go 的 scSectionProcess 在开启诊断开关时附加 `proc_goroutineleak` 检查项。
// 默认开关文件 run/diag_goroutineleak.enabled 不存在时返回 (scItem{}, false), 零额外 GC 开销。
func scGoroutineLeakItem(c *scCtx) (scItem, bool) {
	if c == nil || c.env == nil {
		return scItem{}, false
	}
	flagOn := false
	if c.env.Exists != nil && c.env.Exists(c.hnc("run", "diag_goroutineleak.enabled")) {
		flagOn = true
	} else if c.env.Getenv != nil && dpParamTruthy(c.env.Getenv("HNC_DIAG_GOROUTINELEAK")) {
		flagOn = true
	}
	if !flagOn {
		return scItem{}, false
	}

	sum := sampleGoroutineLeakProfile(true)
	it := scItem{
		ID:    "proc_goroutineleak",
		Label: "协程泄漏检测 (Go 1.27)",
	}
	if sum == nil || !sum.Supported {
		it.Status = scInfo
		it.Value = "当前运行时不支持 goroutineleak"
		return it, true
	}
	if sum.Status == "error" {
		it.Status = scWarn
		it.Value = "采样失败"
		it.Detail = sum.Message
		return it, true
	}
	if sum.LeakedCount > 0 {
		it.Status = scWarn
		it.Value = fmt.Sprintf("检测到 %d 个泄漏协程 (总协程 %d)", sum.LeakedCount, sum.TotalGoroutines)
		if len(sum.PreviewStacks) > 0 {
			it.Detail = scShort(strings.ReplaceAll(sum.PreviewStacks[0], "\n", " · "), 220)
		}
		it.Fix = "请导出诊断包定位阻塞 channel/mutex 调用栈，必要时在设置中重启服务回收协程"
		return it, true
	}
	it.Status = scOK
	it.Value = fmt.Sprintf("0 泄漏 · 当前协程 %d", sum.TotalGoroutines)
	it.Detail = fmt.Sprintf("Go 1.27 runtime/pprof goroutineleak GC 可达性核验耗时 %d ms", sum.DurationMs)
	return it, true
}

// ── 数据面全链路采集、快照差分与四态根因判定主引擎 ──────────────────────

type dpControlledSpec struct {
	mac           string
	name          string
	ip            string
	online        bool
	devTotalBytes uint64
	blacklisted   bool
	limitEnabled  bool
	markID        int
	downMbps      float64
	upMbps        float64
	appQoS        bool
	sqmEnabled    bool
	delayEnabled  bool
	appLimits     []dpIndexedAppLimit
}

type dpIndexedAppLimit struct {
	globalIdx int // 对应 apply_app_limits.sh 顺序分配的 1:9001 + globalIdx
	item      AppLimitItem
}

type dpReadHealth struct {
	downHTBReadOK  bool
	tcFilterReadOK bool
	iptFilterV4OK  bool
	iptFilterV6OK  bool
}

// runDataplaneVerify 执行一次完整的数据面命中核验与根因判定。
func runDataplaneVerify(env *dpVerifyEnv, opts dpVerifyOptions) *DataplaneVerifyReport {
	now := env.Now()
	snaps := env.Snaps
	if snaps == nil {
		snaps = globalDPVerifySnaps
	}
	if opts.ResetBaseline {
		snaps.reset()
	}
	snaps.runsCount.Add(1)

	iface, hotspotActive := dpResolveHotspotIface(env, opts.IfaceOverride)
	uplinkIface := env.UplinkIface
	if uplinkIface == "" {
		uplinkIface = dpDefaultUplinkIFB
	}

	// 1. 读取配置与在线设备元数据
	specs, quicBlockCfg := dpLoadControlledSpecs(env)

	// 2. 读取下行热点口与上行 ifb0 的 HTB 队列统计(优先 Go 原生 Netlink, 失败自动回退 tc -s 文本)
	downStats, downEngine, downHTBOK := dpCollectHTBStats(env, iface, hotspotActive)
	upStats, _, _ := dpCollectHTBStats(env, uplinkIface, hotspotActive)
	engineMode := downEngine
	if engineMode == "" {
		engineMode = dpEngineShellCompat
	}

	// 3. 读取 tc filter 规则、clsact/BPF Maps、CONNMARK 正交高位掩码及 offload_guard 状态
	tcEgressFilters := ""
	tcIngressFilters := ""
	tcIFBFilters := ""
	iptMangleV4 := ""
	iptMangleV6 := ""
	iptFilterV4 := ""
	iptFilterV6 := ""
	readHealth := dpReadHealth{
		downHTBReadOK:  downHTBOK,
		tcFilterReadOK: true,
		iptFilterV4OK:  true,
		iptFilterV6OK:  true,
	}

	if hotspotActive && iface != "" {
		tcIngressFilters = dpCollectIngressFilters(env, iface)
		if env.RunCmd != nil {
			var errTC, errV4, errV6 error
			tcEgressFilters, errTC = dpRunQuickErr(env, "tc", "filter", "show", "dev", iface)
			if errTC != nil {
				readHealth.tcFilterReadOK = false
			}
			tcIFBFilters = dpRunQuick(env, "tc", "filter", "show", "dev", uplinkIface)
			iptMangleV4 = dpRunIptablesQuick(env, "iptables", "-t", "mangle", "-S")
			iptMangleV6 = dpRunIptablesQuick(env, "ip6tables", "-t", "mangle", "-S")
			iptFilterV4, errV4 = dpRunIptablesQuickErr(env, "iptables", "-t", "filter", "-S")
			if errV4 != nil {
				readHealth.iptFilterV4OK = false
			}
			iptFilterV6, errV6 = dpRunIptablesQuickErr(env, "ip6tables", "-t", "filter", "-S")
			if errV6 != nil {
				readHealth.iptFilterV6OK = false
			}
		} else {
			readHealth.tcFilterReadOK = false
			readHealth.iptFilterV4OK = false
			readHealth.iptFilterV6OK = false
		}
	}

	markLayout, low16Protected := checkNetdLow16Protection(iptMangleV4, iptMangleV6, tcEgressFilters)
	offGuard, offloadRawState := dpInspectOffloadGuard(env)
	bpfMaps := dpInspectBPFMaps(env, iface, hotspotActive, tcIngressFilters, offGuard)
	// 若 offload_guard 未显式记录 tether_offload_disabled, 结合 tether_limit_zeroed 与 slowpath 综合反映
	if !offGuard.TetherOffloadDisabled && offGuard.SlowpathActive && bpfMaps.TetherLimitZeroed {
		offGuard.TetherOffloadDisabled = true
	}
	ipv6QUICControlled := dpCheckIPv6QUICControlled(quicBlockCfg, iptFilterV6)

	fwFlowMap := parseTCFWFilterHandles(tcEgressFilters)
	u32ClassSet := parseTCFilterFlowIDs(tcEgressFilters)
	upFilterClassSet := parseTCFilterFlowIDs(tcIFBFilters)
	policeActive := strings.Contains(tcIngressFilters, "police")

	// 4. 逐台受控设备计算增量并输出根因判定
	devicesOut := make([]DataplaneDeviceEntry, 0, len(specs))
	var hitCnt, idleCnt, unavailCnt, errCnt int

	for _, sp := range specs {
		entry := dpEvaluateDevice(
			env,
			snaps,
			now,
			iface,
			uplinkIface,
			hotspotActive,
			sp,
			readHealth,
			downStats,
			upStats,
			fwFlowMap,
			u32ClassSet,
			upFilterClassSet,
			policeActive,
			iptFilterV4,
			iptFilterV6,
			bpfMaps,
			offGuard,
			offloadRawState,
		)
		switch entry.Verdict {
		case "hit":
			hitCnt++
		case "idle":
			idleCnt++
		case "unavailable":
			unavailCnt++
		default:
			errCnt++
		}
		devicesOut = append(devicesOut, entry)
	}

	summary := dpBuildSummary(hotspotActive, readHealth, devicesOut, hitCnt, idleCnt, unavailCnt, errCnt)

	// 5. Go 1.27 goroutineleak 按需零闲置开销采样
	var leakSum *GoroutineLeakSummary
	if doLeak, leakTrig := shouldRunGoroutineLeakDiag(env, opts); doLeak {
		leakSum = sampleGoroutineLeakProfile(true)
		if leakSum != nil && leakSum.Trigger == "" {
			leakSum.Trigger = leakTrig
		}
	}

	return &DataplaneVerifyReport{
		OK:                 true,
		CheckedAt:          now.Unix(),
		Iface:              iface,
		HotspotActive:      hotspotActive,
		EngineMode:         engineMode,
		MarkLayout:         markLayout,
		NetdLow16Protected: low16Protected,
		IPv6QUICControlled: ipv6QUICControlled,
		ReasonCode:         summary.ReasonCode,
		Advice:             summary.Advice,
		BPFMaps:            bpfMaps,
		OffloadGuard:       offGuard,
		Summary:            summary,
		Devices:            devicesOut,
		GoroutineLeak:      leakSum,
	}
}

func dpResolveHotspotIface(env *dpVerifyEnv, override string) (string, bool) {
	if override != "" {
		return override, true
	}
	if b, err := env.ReadFile(filepath.Join(env.HNCDir, "run", "hnc_state")); err == nil {
		st := strings.TrimSpace(string(b))
		if strings.HasPrefix(st, "ACTIVE:") {
			ifc := dpSanitizeIface(strings.TrimPrefix(st, "ACTIVE:"))
			if ifc != "" {
				return ifc, true
			}
		}
	}
	if b, err := env.ReadFile(filepath.Join(env.HNCDir, "run", "iface.cache")); err == nil {
		lines := strings.Split(string(b), "\n")
		if len(lines) > 0 {
			if ifc := dpSanitizeIface(lines[0]); ifc != "" {
				return ifc, false
			}
		}
	}
	return "", false
}

func dpCollectHTBStats(env *dpVerifyEnv, dev string, hotspotActive bool) (map[string]TCClassStats, string, bool) {
	if !hotspotActive || dev == "" {
		return map[string]TCClassStats{}, dpEngineGoOrCompatDefault(env), true
	}
	if env.DumpHTBNetlink != nil && env.Ifindex != nil {
		if idx := env.Ifindex(dev); idx > 0 {
			if stats, err := env.DumpHTBNetlink(idx); err == nil && stats != nil {
				// 当接口尚未挂任何 HTB 类但存在 shell 输出时允许兜底校验; 有类直接走原生 Netlink
				if len(stats) > 0 {
					return stats, dpEngineNativeNetlink, true
				}
				if env.RunCmd == nil {
					return stats, dpEngineNativeNetlink, true
				}
				txt, sErr := dpRunQuickErr(env, "tc", "-s", "class", "show", "dev", dev)
				if sErr != nil {
					return stats, dpEngineNativeNetlink, true
				}
				parsed := parseTCStatsText(txt)
				if len(parsed) == 0 {
					return stats, dpEngineNativeNetlink, true
				}
				return parsed, dpEngineShellCompat, true
			}
		}
	}
	if env.RunCmd != nil {
		txt, err := dpRunQuickErr(env, "tc", "-s", "class", "show", "dev", dev)
		if err != nil {
			return map[string]TCClassStats{}, dpEngineShellCompat, false
		}
		return parseTCStatsText(txt), dpEngineShellCompat, true
	}
	return map[string]TCClassStats{}, dpEngineShellCompat, false
}

func dpEngineGoOrCompatDefault(env *dpVerifyEnv) string {
	if env != nil && env.DumpHTBNetlink != nil {
		return dpEngineNativeNetlink
	}
	return dpEngineShellCompat
}

func dpRunQuickErr(env *dpVerifyEnv, name string, args ...string) (string, error) {
	if env == nil || env.RunCmd == nil {
		return "", fmt.Errorf("%s: runner unavailable", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dpCmdTimeout)
	defer cancel()
	return env.RunCmd(ctx, name, args...)
}

func dpRunQuick(env *dpVerifyEnv, name string, args ...string) string {
	out, _ := dpRunQuickErr(env, name, args...)
	return out
}

func dpRunIptablesQuickErr(env *dpVerifyEnv, bin string, args ...string) (string, error) {
	if env == nil || env.RunCmd == nil {
		return "", fmt.Errorf("%s: runner unavailable", bin)
	}
	tryArgs := func(a []string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dpCmdTimeout)
		defer cancel()
		return env.RunCmd(ctx, bin, a...)
	}
	out1, err1 := tryArgs(append([]string{"-w", "2"}, args...))
	if err1 == nil {
		return out1, nil
	}
	if !isXtablesWaitFlagError(out1 + " " + err1.Error()) {
		return out1, err1
	}
	out2, err2 := tryArgs(append([]string{"-w"}, args...))
	if err2 == nil {
		return out2, nil
	}
	if isXtablesWaitFlagError(out2 + " " + err2.Error()) {
		return tryArgs(args)
	}
	return out2, err2
}

func dpRunIptablesQuick(env *dpVerifyEnv, bin string, args ...string) string {
	out, _ := dpRunIptablesQuickErr(env, bin, args...)
	return out
}

func hasValidIngressFilterLines(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return false
	}
	for _, kw := range []string{"pref ", "prio ", "police", "hnc_clsact", "direct-action", "mirred", "u32", "fw "} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// dpCollectIngressFilters 针对 ColorOS /system/bin/tc 对 `ingress` 关键字返回空串或报错的缺陷,
// 优先支持原生 RTNetlink RTM_GETTFILTER 查询, 并在 shell 路径依次回退 `ingress` -> `parent ffff:` -> `parent ffff:fff2`。
func dpCollectIngressFilters(env *dpVerifyEnv, iface string) string {
	if env == nil || iface == "" {
		return ""
	}
	if env.DumpIngressNetlink != nil && env.Ifindex != nil {
		if idx := env.Ifindex(iface); idx > 0 {
			if nlOut := env.DumpIngressNetlink(idx); hasValidIngressFilterLines(nlOut) {
				return nlOut
			}
		}
	}
	if env.RunCmd == nil {
		return ""
	}
	out := dpRunQuick(env, "tc", "filter", "show", "dev", iface, "ingress")
	if hasValidIngressFilterLines(out) {
		return out
	}
	if fb1 := dpRunQuick(env, "tc", "filter", "show", "dev", iface, "parent", "ffff:"); hasValidIngressFilterLines(fb1) {
		return fb1
	}
	if fb2 := dpRunQuick(env, "tc", "filter", "show", "dev", iface, "parent", "ffff:fff2"); hasValidIngressFilterLines(fb2) {
		return fb2
	}
	return out
}

// dpLoadControlledSpecs 聚合 rules.json + app_limits.json + devices.json + device_names.json。
func dpLoadControlledSpecs(env *dpVerifyEnv) ([]dpControlledSpec, bool) {
	rulesMap := dpReadJSONMap(env, filepath.Join(env.HNCDir, "data", "rules.json"))
	devsMap := dpReadJSONMap(env, filepath.Join(env.HNCDir, "data", "devices.json"))
	namesMap := dpReadJSONMap(env, filepath.Join(env.HNCDir, "data", "device_names.json"))
	appLimits := dpReadAppLimits(env)

	quicBlock := dpJSONBool(rulesMap["quic_block"])

	blSet := make(map[string]bool)
	if blRaw, ok := rulesMap["blacklist"].([]interface{}); ok {
		for _, item := range blRaw {
			if s, ok := item.(string); ok {
				if cm := canonMAC(s); cm != "" {
					blSet[cm] = true
				}
			}
		}
	}

	appByMAC := make(map[string][]dpIndexedAppLimit)
	validIdx := 0
	for _, it := range appLimits {
		cm := canonMAC(it.MAC)
		if cm == "" || it.DownMbps <= 0 || math.IsNaN(it.DownMbps) {
			continue
		}
		appByMAC[cm] = append(appByMAC[cm], dpIndexedAppLimit{
			globalIdx: validIdx,
			item: AppLimitItem{
				MAC:      cm,
				AppID:    it.AppID,
				DownMbps: it.DownMbps,
			},
		})
		validIdx++
	}

	devRulesRaw, _ := rulesMap["devices"].(map[string]interface{})

	// 收集所有候选受控 MAC(排序保证输出稳定可测)
	macSet := make(map[string]bool)
	for rawMAC := range devRulesRaw {
		if cm := canonMAC(rawMAC); cm != "" {
			macSet[cm] = true
		}
	}
	for cm := range blSet {
		macSet[cm] = true
	}
	for cm := range appByMAC {
		macSet[cm] = true
	}

	macList := make([]string, 0, len(macSet))
	for cm := range macSet {
		macList = append(macList, cm)
	}
	sort.Strings(macList)

	nowUnix := env.Now().Unix()
	specs := make([]dpControlledSpec, 0, len(macList))
	for _, mac := range macList {
		ruleObj := dpLookupCaseInsensitiveObj(devRulesRaw, mac)
		devObj := dpLookupCaseInsensitiveObj(devsMap, mac)

		limitEnabled := dpJSONBool(ruleObj["limit_enabled"])
		downMbps := dpJSONFloat(ruleObj["down_mbps"])
		upMbps := dpJSONFloat(ruleObj["up_mbps"])
		appQoS := dpJSONBool(ruleObj["app_qos"])
		sqmEnabled := dpJSONBool(ruleObj["sqm_enabled"])
		delayEnabled := dpJSONBool(ruleObj["delay_enabled"])
		markID := int(dpJSONFloat(ruleObj["mark_id"]))
		blacklisted := blSet[mac]
		apps := appByMAC[mac]

		hasActiveRateLimit := limitEnabled && (downMbps > 0 || upMbps > 0)
		isControlled := hasActiveRateLimit || appQoS || blacklisted || len(apps) > 0 || sqmEnabled || delayEnabled
		if !isControlled {
			continue
		}

		ip := strings.TrimSpace(dpJSONString(devObj["ip"]))
		if ip == "" {
			ip = strings.TrimSpace(dpJSONString(ruleObj["ip"]))
		}
		online := dpInferDeviceOnline(devObj, nowUnix)
		devBytes := dpJSONUint64(devObj["rx_bytes"]) + dpJSONUint64(devObj["tx_bytes"])
		if devBytes == 0 {
			devBytes = dpJSONUint64(devObj["bytes_total"])
		}

		name := dpLookupDeviceName(namesMap, devObj, mac)

		specs = append(specs, dpControlledSpec{
			mac:           mac,
			name:          name,
			ip:            ip,
			online:        online,
			devTotalBytes: devBytes,
			blacklisted:   blacklisted,
			limitEnabled:  hasActiveRateLimit,
			markID:        markID,
			downMbps:      downMbps,
			upMbps:        upMbps,
			appQoS:        appQoS,
			sqmEnabled:    sqmEnabled,
			delayEnabled:  delayEnabled,
			appLimits:     apps,
		})
	}
	return specs, quicBlock
}

func dpEvaluateDevice(
	env *dpVerifyEnv,
	snaps *dpVerifySnapshotStore,
	now time.Time,
	iface string,
	uplinkIface string,
	hotspotActive bool,
	sp dpControlledSpec,
	readHealth dpReadHealth,
	downStats map[string]TCClassStats,
	upStats map[string]TCClassStats,
	fwFlowMap map[string]uint32,
	u32ClassSet map[string]bool,
	upFilterClassSet map[string]bool,
	policeActive bool,
	iptFilterV4 string,
	iptFilterV6 string,
	bpfMaps DataplaneBPFMaps,
	offGuard DataplaneOffloadGuard,
	offloadRawState string,
) DataplaneDeviceEntry {
	classID := dpClassIDForMark(sp.markID)
	markVal := dpMarkForDevice(sp.markID, classID, fwFlowMap)
	markHex := ""
	if markVal != 0 {
		markHex = fmt.Sprintf("0x%08x", markVal)
	}

	downSt, downClassPresent := dpLookupDeviceHTBStats(downStats, classID, sp.markID, sp.appQoS)
	upSt, upClassPresent := dpLookupDeviceHTBStats(upStats, classID, sp.markID, false)

	var downDeltaBytes, downDeltaDrops uint64
	var downObsKbps float64
	if downClassPresent && iface != "" {
		downDeltaBytes, downDeltaDrops, downObsKbps = snaps.observeAndDiff(
			iface+"|down|"+classID, now, downSt.SentBytes, downSt.Drops,
		)
	}

	var upDeltaBytes, upDeltaDrops uint64
	var upObsKbps float64
	if upClassPresent && uplinkIface != "" {
		upDeltaBytes, upDeltaDrops, upObsKbps = snaps.observeAndDiff(
			uplinkIface+"|up|"+classID, now, upSt.SentBytes, upSt.Drops,
		)
	}

	// 单应用限速子类核验
	appEntries := make([]DataplaneAppClassEntry, 0, len(sp.appLimits))
	var anyAppMissing, anyAppHit bool
	var appSentSum, appDeltaSum, appDropsSum, appOverlimitsSum uint64

	for _, al := range sp.appLimits {
		minor := dpAppClassMinBase + 1 + al.globalIdx
		appCID := fmt.Sprintf("1:%x", minor)
		ast, present := downStats[appCID]
		var aDeltaB, aDeltaD uint64
		var aKbps float64
		if present && iface != "" {
			aDeltaB, aDeltaD, aKbps = snaps.observeAndDiff(
				iface+"|app|"+appCID, now, ast.SentBytes, ast.Drops,
			)
		}
		aVerdict := "idle"
		if !hotspotActive {
			aVerdict = "idle"
		} else if !readHealth.downHTBReadOK {
			aVerdict = "unavailable"
		} else if !present {
			if sp.online {
				aVerdict = "missing_class"
				anyAppMissing = true
			}
		} else if aDeltaB > 0 || ast.SentBytes > 0 {
			aVerdict = "hit"
			anyAppHit = true
		}
		appSentSum += ast.SentBytes
		appDeltaSum += aDeltaB
		appDropsSum += ast.Drops
		appOverlimitsSum += ast.Overlimits

		appEntries = append(appEntries, DataplaneAppClassEntry{
			AppID:         al.item.AppID,
			ClassID:       appCID,
			ParentClassID: ast.ParentID,
			DownLimitMbps: al.item.DownMbps,
			ClassPresent:  present,
			SentBytes:     ast.SentBytes,
			DeltaBytes:    aDeltaB,
			Drops:         ast.Drops,
			DeltaDrops:    aDeltaD,
			Overlimits:    ast.Overlimits,
			ObservedKbps:  aKbps,
			Verdict:       aVerdict,
		})
	}

	// 若仅开启单应用限速而未开整机限速, 将单应用累计并入设备下行观测展示便于直观排障
	if !sp.limitEnabled && !sp.appQoS && len(appEntries) > 0 && !downClassPresent {
		downSt.SentBytes = appSentSum
		downDeltaBytes = appDeltaSum
		downSt.Drops = appDropsSum
		downSt.Overlimits = appOverlimitsSum
	}

	// 客户端活跃流量检测(结合 devices.json 增量与 RateLoop 实时速率)
	devDeltaBytes, hadPrevDevSnap := snaps.observeDeviceBytes(iface, sp.mac, now, sp.devTotalBytes)
	liveBps := int64(0)
	if env.LiveDeviceBps != nil {
		liveBps = env.LiveDeviceBps(sp.mac)
	}

	effDownDelta := downDeltaBytes
	if appDeltaSum > effDownDelta {
		effDownDelta = appDeltaSum
	}
	htbCapturedDelta := effDownDelta + upDeltaBytes
	var captureRatio float64
	if devDeltaBytes > 0 {
		r := float64(htbCapturedDelta) / float64(devDeltaBytes)
		if r > 1.0 {
			r = 1.0
		}
		captureRatio = math.Round(r*1000) / 1000
	}

	verdict, reasonCode, label, reason, advice, fix := dpComputeDeviceVerdictEx(
		hotspotActive,
		sp,
		readHealth,
		classID,
		downClassPresent,
		upClassPresent,
		downSt,
		upSt,
		effDownDelta,
		upDeltaBytes,
		devDeltaBytes,
		hadPrevDevSnap,
		liveBps,
		anyAppMissing,
		anyAppHit,
		fwFlowMap,
		u32ClassSet,
		upFilterClassSet,
		policeActive,
		iptFilterV4,
		iptFilterV6,
		bpfMaps,
		offGuard,
		offloadRawState,
	)

	effDownMbps := 0.0
	effUpMbps := 0.0
	if sp.limitEnabled {
		effDownMbps = sp.downMbps
		effUpMbps = sp.upMbps
	}

	return DataplaneDeviceEntry{
		MAC:              sp.mac,
		Name:             sp.name,
		IP:               sp.ip,
		Online:           sp.online,
		Blacklisted:      sp.blacklisted,
		MarkID:           sp.markID,
		MarkHex:          markHex,
		ClassID:          classID,
		DownLimitMbps:    effDownMbps,
		UpLimitMbps:      effUpMbps,
		AppQoS:           sp.appQoS,
		AppLimitsCount:   len(sp.appLimits),
		DevDeltaBytes:    devDeltaBytes,
		CaptureRatio:     captureRatio,
		DownSentBytes:    downSt.SentBytes,
		DownDeltaBytes:   downDeltaBytes,
		DownDrops:        downSt.Drops,
		DownDeltaDrops:   downDeltaDrops,
		DownOverlimits:   downSt.Overlimits,
		DownObservedKbps: downObsKbps,
		UpSentBytes:      upSt.SentBytes,
		UpDeltaBytes:     upDeltaBytes,
		UpDrops:          upSt.Drops,
		UpDeltaDrops:     upDeltaDrops,
		UpOverlimits:     upSt.Overlimits,
		UpObservedKbps:   upObsKbps,
		Verdict:          verdict,
		ReasonCode:       reasonCode,
		StatusLabel:      label,
		Reason:           reason,
		Advice:           advice,
		Fix:              fix,
		AppClasses:       appEntries,
	}
}

func dpComputeDeviceVerdict(
	hotspotActive bool,
	sp dpControlledSpec,
	classID string,
	downClassPresent bool,
	upClassPresent bool,
	downSt TCClassStats,
	upSt TCClassStats,
	downDeltaBytes uint64,
	upDeltaBytes uint64,
	anyAppMissing bool,
	anyAppHit bool,
	clientHasTraffic bool,
	fwFlowMap map[string]uint32,
	u32ClassSet map[string]bool,
	upFilterClassSet map[string]bool,
	policeActive bool,
	iptFilterV4 string,
	iptFilterV6 string,
	bpfMaps DataplaneBPFMaps,
	offGuard DataplaneOffloadGuard,
	offloadRawState string,
) (verdict, label, reason, fix string) {
	var synthDevDelta uint64
	if clientHasTraffic {
		synthDevDelta = dpActiveTrafficBytes
	}
	v, _, lbl, rsn, _, fx := dpComputeDeviceVerdictEx(
		hotspotActive,
		sp,
		dpReadHealth{downHTBReadOK: true, tcFilterReadOK: true, iptFilterV4OK: true, iptFilterV6OK: true},
		classID,
		downClassPresent,
		upClassPresent,
		downSt,
		upSt,
		downDeltaBytes,
		upDeltaBytes,
		synthDevDelta,
		clientHasTraffic,
		0,
		anyAppMissing,
		anyAppHit,
		fwFlowMap,
		u32ClassSet,
		upFilterClassSet,
		policeActive,
		iptFilterV4,
		iptFilterV6,
		bpfMaps,
		offGuard,
		offloadRawState,
	)
	return v, lbl, rsn, fx
}

func dpComputeDeviceVerdictEx(
	hotspotActive bool,
	sp dpControlledSpec,
	readHealth dpReadHealth,
	classID string,
	downClassPresent bool,
	upClassPresent bool,
	downSt TCClassStats,
	upSt TCClassStats,
	downDeltaBytes uint64,
	upDeltaBytes uint64,
	devDeltaBytes uint64,
	hadPrevDevSnap bool,
	liveBps int64,
	anyAppMissing bool,
	anyAppHit bool,
	fwFlowMap map[string]uint32,
	u32ClassSet map[string]bool,
	upFilterClassSet map[string]bool,
	policeActive bool,
	iptFilterV4 string,
	iptFilterV6 string,
	bpfMaps DataplaneBPFMaps,
	offGuard DataplaneOffloadGuard,
	offloadRawState string,
) (verdict, reasonCode, label, reason, advice, fix string) {
	if !hotspotActive {
		return "idle", "", "热点未开启", "热点当前处于关闭状态，待热点激活后自动挂载内核 HTB 队列", "", ""
	}

	// 黑名单阻断最高优先级裁决: 无论是否同时配置了 HTB 限速/QoS/单应用限速,
	// HNC_CTRL 在转发层直接丢弃/拒绝数据包(流量不会进入出口 HTB 队列), 优先核验双栈阻断规则!
	if sp.blacklisted {
		if !readHealth.iptFilterV4OK || !readHealth.iptFilterV6OK {
			return "unavailable", "iptables_read_failed", "防火墙不可读",
				"无法读取内核 iptables/ip6tables 防火墙规则，暂无法核验黑名单阻断状态（严禁伪报空闲或生效）",
				"请确认后台服务具备完整 Root 权限并点击重新检验",
				"检查 Root 权限后重试数据面检验"
		}
		macUpper := strings.ToUpper(sp.mac)
		macLower := strings.ToLower(sp.mac)
		if iptFilterV4 != "" && !strings.Contains(iptFilterV4, macUpper) && !strings.Contains(iptFilterV4, macLower) {
			return "missing_rule", "blacklist_v4_missing", "阻断规则缺失",
				"设备处于黑名单，但内核 HNC_CTRL 链缺少对应 MAC 阻断规则，点击立即重下发修复",
				"",
				"点击「重新下发规则」同步双栈黑名单防火墙链"
		}
		if iptFilterV6 != "" && strings.Contains(iptFilterV6, "HNC_CTRL") &&
			!strings.Contains(iptFilterV6, macUpper) && !strings.Contains(iptFilterV6, macLower) {
			return "missing_rule", "blacklist_v6_missing", "IPv6 阻断缺失",
				"IPv4 黑名单已挂载，但 ip6tables HNC_CTRL 缺少对应 MAC 规则",
				"",
				"点击「重新下发规则」补齐 IPv6 黑名单规则"
		}
		return "hit", "", "黑名单阻断生效", "双栈防火墙 HNC_CTRL MAC 阻断规则已就绪并拦截该设备转发流量", "", ""
	}

	// 若内核 tc HTB 类或过滤器读取失败, 严禁假报 idle 或误报 missing!
	if !readHealth.downHTBReadOK || !readHealth.tcFilterReadOK {
		return "unavailable", "tc_read_failed", "流控队列不可读",
			"无法读取内核 tc 流控队列或过滤器状态，暂无法确认限速规则是否命中（严禁伪报空闲）",
			"请确认手机 Root 权限正常及内核支持 Netlink/tc 查询后重试",
			"检查系统权限后重新执行数据面检验"
	}

	needDownClass := (sp.limitEnabled && sp.downMbps > 0) || sp.appQoS || sp.sqmEnabled || sp.delayEnabled
	needUpClass := sp.limitEnabled && sp.upMbps > 0

	// 1. 检查 missing_class: 配置开启了限速但内核缺少对应 1:<cid> HTB 类
	if needDownClass && (classID == "" || !downClassPresent) {
		return "missing_class", "htb_down_class_missing", "内核队列缺失",
			"内核队列缺失（可能被系统 netd 重置），点击立即重下发修复",
			"",
			"点击「立即重下发修复」重建下行 HTB 队列与正交掩码分类器"
	}
	if needUpClass && !upClassPresent && !policeActive {
		return "missing_class", "htb_up_class_missing", "上行队列缺失",
			"上行 ifb0 内核 HTB 队列及 ingress police 兜底均缺失（可能被系统重置），点击立即重下发修复",
			"",
			"点击「立即重下发修复」重建 ifb0 上行队列与 clsact prio 2 重定向"
	}
	if anyAppMissing {
		return "missing_class", "htb_app_class_missing", "应用子类缺失",
			"单应用限速配置已开启，但内核缺少对应 1:900x HTB 子类（可能被系统 netd 重置），点击立即重下发修复",
			"",
			"点击「立即重下发修复」重新同步单应用限速 HTB 子类与 IP 映射"
	}

	// 2. 检查 missing_rule: HTB 类存在但当已采集到 tc filter 输出时未发现任何指向该类的 fw / u32 过滤器
	if needDownClass && len(fwFlowMap)+len(u32ClassSet) > 0 {
		_, hasFW := fwFlowMap[classID]
		hasU32 := u32ClassSet[classID]
		if !hasFW && !hasU32 {
			return "missing_rule", "tc_down_filter_missing", "掩码过滤器缺失",
				"内核 HTB 队列存在，但缺少指向 " + classID + " 的 fw 高位掩码或 u32 过滤器，点击立即重下发修复",
				"",
				"点击「立即重下发修复」恢复 tc fw 0xffff0000 正交掩码过滤器"
		}
	}
	if needUpClass && upClassPresent && len(upFilterClassSet) > 0 && !upFilterClassSet[classID] {
		return "missing_rule", "tc_up_filter_missing", "上行过滤器缺失",
			"ifb0 上行 HTB 类存在，但缺少指向 " + classID + " 的分类过滤器，点击立即重下发修复",
			"",
			"点击「立即重下发修复」同步上行 ifb0 过滤器与 IPv6 邻居规则"
	}

	// 3. 高通/异构硬件加速截流比例检测:
	//    (a) 采样窗口内客户端有明显实际收发增量(>= 64 KiB), 但 tc HTB 捕获字节不足实际流量的 30%
	//        (即使有少量 TCP 握手包走软件栈使 htbDelta > 0, 大流量走 tether_limit_map / IPA / HNAT 快路径直通亦精准检出!);
	//    (b) 或 htbDelta == 0 且客户端在当前窗口有真实活跃流量(或首帧累计活跃且存在硬件加速未压制信号)。
	htbDelta := downDeltaBytes + upDeltaBytes
	htbTotalSent := downSt.SentBytes + upSt.SentBytes
	offloadSuspect := !bpfMaps.TetherLimitZeroed ||
		bpfMaps.TetherFlowEntries > 0 ||
		offloadRawState == "ACTIVE" ||
		(!offGuard.SlowpathActive && !offGuard.TetherOffloadDisabled) ||
		offGuard.HWNAT == "detected_no_knob" ||
		offGuard.HWNAT == "failed"

	ratioBypass := sp.online && devDeltaBytes >= dpBypassWindowMinBytes &&
		float64(htbDelta) < float64(devDeltaBytes)*dpBypassCaptureMinRatio
	zeroCaptureBypass := sp.online && htbDelta == 0 &&
		((hadPrevDevSnap && devDeltaBytes >= dpActiveTrafficBytes) ||
			liveBps >= 1024 ||
			(!hadPrevDevSnap && htbTotalSent == 0 && sp.devTotalBytes >= dpBypassWindowMinBytes && offloadSuspect))

	if ratioBypass || zeroCaptureBypass {
		rc := "hw_offload_bypass"
		if bpfMaps.TetherBPFDetected {
			rc = "qcom_tether_bpf_bypass"
		}
		var detailReason string
		if devDeltaBytes >= dpBypassWindowMinBytes {
			pct := float64(htbDelta) * 100.0 / float64(devDeltaBytes)
			detailReason = fmt.Sprintf("采样窗口内客户端实际收发 %s，但流控队列仅捕获 %s（%.1f%% < 30%%）；%s",
				formatDPBytesMB(devDeltaBytes), formatDPBytesMB(htbDelta), pct, dpBypassDualPathAdvice)
		} else {
			detailReason = dpBypassDualPathAdvice
		}
		return "bypass", rc, "硬件加速截流", detailReason, dpBypassDualPathAdvice, dpBypassDualPathAdvice
	}

	// 4. 检查 hit: HTB 队列存在且 delta_bytes > 0 或累计 sent_bytes > 0
	if htbDelta > 0 || htbTotalSent > 0 || anyAppHit {
		totalShapeEvents := downSt.Overlimits + downSt.Drops + upSt.Overlimits + upSt.Drops
		return "hit", "", "队列真实命中",
			fmt.Sprintf("内核 HTB 限速队列已真实命中（累计转发 %s，超限整形/丢包 %d 次）",
				formatDPBytesMB(htbTotalSent), totalShapeEvents),
			"", ""
	}

	// 5. idle: 链路完整就绪, 等待客户端产生流量
	if !sp.online {
		return "idle", "", "就绪（设备离线）", "规则链路完整就绪，当前设备离线，重连产生流量后将自动命中队列", "", ""
	}
	return "idle", "", "链路就绪（空闲）", "规则链路完整就绪，等待客户端产生流量", "", ""
}

func dpBuildSummary(hotspotActive bool, readHealth dpReadHealth, devs []DataplaneDeviceEntry, hitCnt, idleCnt, unavailCnt, errCnt int) DataplaneSummary {
	total := len(devs)
	if !hotspotActive {
		return DataplaneSummary{
			ControlledDevices:    total,
			HittingCount:         hitCnt,
			IdleCount:            idleCnt,
			UnavailableCount:     unavailCnt,
			BypassOrMissingCount: errCnt,
			OverallStatus:        "idle",
			Headline:             "热点当前未开启，开启热点后可实时核验内核 HTB 限速队列命中计数",
		}
	}
	if !readHealth.downHTBReadOK && total == 0 {
		return DataplaneSummary{
			ControlledDevices: 0,
			UnavailableCount:  1,
			OverallStatus:     "unavailable",
			ReasonCode:        "tc_read_failed",
			Headline:          "无法读取内核 tc 流控队列状态，请确认 Root 权限与内核 Netlink 支持",
		}
	}
	if total == 0 {
		return DataplaneSummary{
			ControlledDevices: 0,
			OverallStatus:     "ok",
			Headline:          "热点运行中，当前未配置受控限速、应用 QoS 或黑名单设备",
		}
	}
	if errCnt > 0 {
		bypassCode := ""
		for _, d := range devs {
			if d.Verdict == "bypass" || d.Verdict == "bypass_offload" {
				bypassCode = d.ReasonCode
				if bypassCode == "" {
					bypassCode = "hw_offload_bypass"
				}
				break
			}
		}
		if bypassCode != "" {
			return DataplaneSummary{
				ControlledDevices:    total,
				HittingCount:         hitCnt,
				IdleCount:            idleCnt,
				UnavailableCount:     unavailCnt,
				BypassOrMissingCount: errCnt,
				OverallStatus:        "fail",
				ReasonCode:           bypassCode,
				Headline:             dpBypassDualPathAdvice,
				Advice:               dpBypassDualPathAdvice,
			}
		}
		return DataplaneSummary{
			ControlledDevices:    total,
			HittingCount:         hitCnt,
			IdleCount:            idleCnt,
			UnavailableCount:     unavailCnt,
			BypassOrMissingCount: errCnt,
			OverallStatus:        "warn",
			ReasonCode:           "missing_rule_or_class",
			Headline:             fmt.Sprintf("注意：%d 台受控设备缺少内核 HTB 队列或过滤器，请点击重下发修复", errCnt),
		}
	}
	if unavailCnt > 0 {
		rc := "dataplane_read_failed"
		for _, d := range devs {
			if d.Verdict == "unavailable" && d.ReasonCode != "" {
				rc = d.ReasonCode
				break
			}
		}
		return DataplaneSummary{
			ControlledDevices:    total,
			HittingCount:         hitCnt,
			IdleCount:            idleCnt,
			UnavailableCount:     unavailCnt,
			BypassOrMissingCount: 0,
			OverallStatus:        "unavailable",
			ReasonCode:           rc,
			Headline:             fmt.Sprintf("无法读取 %d 台受控设备的内核流控或防火墙状态，暂不能确认限速生效情况", unavailCnt),
		}
	}
	if hitCnt > 0 {
		return DataplaneSummary{
			ControlledDevices:    total,
			HittingCount:         hitCnt,
			IdleCount:            idleCnt,
			BypassOrMissingCount: 0,
			OverallStatus:        "ok",
			Headline:             fmt.Sprintf("内核限速真实生效：%d/%d 台受控设备已命中 HTB 队列（其余 %d 台空闲就绪）", hitCnt, total, idleCnt),
		}
	}
	return DataplaneSummary{
		ControlledDevices:    total,
		HittingCount:         0,
		IdleCount:            idleCnt,
		BypassOrMissingCount: 0,
		OverallStatus:        "idle",
		Headline:             fmt.Sprintf("全部 %d 台受控设备内核队列与正交掩码链路已就绪，等待客户端产生流量", total),
	}
}

// ── BPF Map、clsact/ifb0 优先级、CONNMARK 高位掩码与 Offload 解析器 ────

// dpDetectSystemTetherBPF 检测系统是否存在 /sys/fs/bpf/tether_* 或 /sys/fs/bpf/tethering/map_offload_tether_* 加速映射。
func dpDetectSystemTetherBPF(env *dpVerifyEnv) bool {
	if env == nil || env.Exists == nil {
		return false
	}
	cands := []string{
		env.BPFTetherLimitPin,
		"/sys/fs/bpf/tether_limit_map",
		"/sys/fs/bpf/tether_downstream6_map",
		"/sys/fs/bpf/tether_downstream4_map",
		"/sys/fs/bpf/tethering/map_offload_tether_limit_map",
		"/sys/fs/bpf/tethering/map_offload_tether_downstream6_map",
		"/sys/fs/bpf/tethering/map_offload_tether_downstream4_map",
		"/sys/fs/bpf/map_offload_tether_downstream6_map",
	}
	for _, p := range cands {
		if p != "" && env.Exists(p) {
			return true
		}
	}
	return false
}

// dpInspectBPFMaps 读取 hnc_clsact_ctl check、BPF 映射真实条目数与 prio 1/prio 2 分离状态。
// 铁律: 严禁拿规则配置文件条数冒充内核 BPF 条目数! 不可读时如实置 BpfMapReadable: false。
func dpInspectBPFMaps(
	env *dpVerifyEnv,
	iface string,
	hotspotActive bool,
	tcIngressFilters string,
	offGuard DataplaneOffloadGuard,
) DataplaneBPFMaps {
	out := DataplaneBPFMaps{
		BpfMapReadable:    false,
		TetherLimitZeroed: true,
		TetherBPFDetected: dpDetectSystemTetherBPF(env),
	}

	// 1. 检查 tether_limit_map 是否全部置 0
	if env.BPFTetherLimitPin != "" && env.Exists != nil && env.Exists(env.BPFTetherLimitPin) {
		out.TetherBPFDetected = true
		if b, err := env.ReadFile(env.BPFTetherLimitPin); err == nil {
			_, allZero, ok := parseTetherLimitMapZeroed(string(b))
			if ok {
				out.TetherLimitZeroed = allZero
			} else {
				out.TetherLimitZeroed = offGuard.SlowpathActive || offGuard.TetherOffloadDisabled
			}
		} else {
			out.TetherLimitZeroed = offGuard.SlowpathActive || offGuard.TetherOffloadDisabled
		}
	}

	if !hotspotActive || iface == "" {
		return out
	}

	// 2. 调用 hnc_clsact_ctl check <iface> 解析 clsact / bpf_filter / 真实 BPF map 遍历计数
	var ctlHasQdisc, ctlHasBPF bool
	var ctlReadableExplicit bool
	var ctlReadableVal bool
	ctlMACCount := -1
	ctlIPCount := -1
	ctlAppPolicyCount := -1
	if env.RunCmd != nil {
		ctlBin := filepath.Join(env.HNCDir, "bin", "hnc_clsact_ctl")
		raw := dpRunQuick(env, ctlBin, "check", iface)
		if strings.TrimSpace(raw) != "" {
			var cm map[string]interface{}
			if json.Unmarshal([]byte(strings.TrimSpace(raw)), &cm) == nil {
				ctlHasQdisc = dpJSONBool(cm["qdisc"])
				ctlHasBPF = dpJSONBool(cm["bpf_filter"])
				if v, ok := cm["bpf_map_readable"].(bool); ok {
					ctlReadableExplicit = true
					ctlReadableVal = v
				}
				if _, ok := cm["mac_entries"]; ok {
					ctlMACCount = int(dpJSONFloat(cm["mac_entries"]))
				}
				if _, ok := cm["ip_entries"]; ok {
					ctlIPCount = int(dpJSONFloat(cm["ip_entries"]))
				}
				if _, ok := cm["app_policy_entries"]; ok {
					ctlAppPolicyCount = int(dpJSONFloat(cm["app_policy_entries"]))
				}
				if v, ok := cm["tether_bpf_present"].(bool); ok && v {
					out.TetherBPFDetected = true
				}
				if _, ok := cm["tether_flow_entries"]; ok {
					if tf := int(dpJSONFloat(cm["tether_flow_entries"])); tf > 0 {
						out.TetherFlowEntries = tf
					}
				}
				if v, ok := cm["tether_limit_zeroed"].(bool); ok {
					out.TetherLimitZeroed = v
				}
			}
		}
	}

	// 3. 解析 tc filter show dev <iface> ingress 校验 prio 1 BPF 与 prio 2 ifb0 mirred 分离
	ingHasBPFPrio1, ingHasIFBPrio2 := parseIngressPrioLayout(tcIngressFilters)
	out.ClsactAttached = (ctlHasQdisc && ctlHasBPF) || ingHasBPFPrio1
	out.IFBRedirectPrio2 = ingHasIFBPrio2

	// 4. 仅采信真实内核 BPF map 遍历计数或可读转储; 不可读时诚实置 BpfMapReadable = false, 绝不拿配置条数假回退!
	anyReadable := false
	if ctlMACCount >= 0 {
		out.MACMarkEntries = ctlMACCount
		anyReadable = true
	} else if n, ok := dpCountPinnedMapEntries(env, env.BPFMACMapPin); ok {
		out.MACMarkEntries = n
		anyReadable = true
	}

	if ctlIPCount >= 0 {
		out.IPMarkEntries = ctlIPCount
		anyReadable = true
	} else if n, ok := dpCountPinnedMapEntries(env, env.BPFIPMapPin); ok {
		out.IPMarkEntries = n
		anyReadable = true
	}

	if ctlAppPolicyCount >= 0 {
		out.AppPolicyEntries = ctlAppPolicyCount
	} else if n, ok := dpCountPinnedMapEntries(env, dpBPFAppPolicyPath); ok {
		out.AppPolicyEntries = n
	}

	if ctlReadableExplicit {
		out.BpfMapReadable = ctlReadableVal || anyReadable
	} else {
		out.BpfMapReadable = anyReadable
	}

	return out
}

func dpCountPinnedMapEntries(env *dpVerifyEnv, pinPath string) (int, bool) {
	if env == nil || pinPath == "" || env.Exists == nil || !env.Exists(pinPath) {
		return 0, false
	}
	if env.ReadFile != nil {
		if b, err := env.ReadFile(pinPath); err == nil {
			return countBPFMapTextEntries(string(b)), true
		}
	}
	return 0, false
}

func countBPFMapTextEntries(raw string) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []interface{}
		if json.Unmarshal([]byte(trimmed), &arr) == nil {
			return len(arr)
		}
	}
	cnt := 0
	for _, ln := range strings.Split(trimmed, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || ln == "{" || ln == "}" || ln == "[]" {
			continue
		}
		if strings.Contains(ln, ":") {
			cnt++
		}
	}
	return cnt
}

// parseTetherLimitMapZeroed 解析 /sys/fs/bpf/tethering/map_offload_tether_limit_map 文本转储。
// 兼容 AOSP BTF pretty-print (`20: 0`, `20: {0}`, `20: 18446744073709551615`) 及 bpftool JSON 数组。
func parseTetherLimitMapZeroed(raw string) (entries int, allZero bool, parsed bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, true, true
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]interface{}
		if json.Unmarshal([]byte(trimmed), &arr) == nil {
			for _, elem := range arr {
				entries++
				if !dpLimitValueIsZero(elem["value"]) {
					return entries, false, true
				}
			}
			return entries, true, true
		}
	}

	allZero = true
	for _, ln := range strings.Split(trimmed, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon <= 0 {
			continue
		}
		valPart := strings.TrimSpace(ln[colon+1:])
		valPart = strings.Trim(valPart, "{}, \t")
		if valPart == "" {
			continue
		}
		fields := strings.Fields(valPart)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 0, 64)
		if err != nil {
			return entries, false, false
		}
		entries++
		if v != 0 {
			allZero = false
		}
	}
	return entries, allZero, true
}

func dpLimitValueIsZero(v interface{}) bool {
	switch tv := v.(type) {
	case float64:
		return tv == 0
	case string:
		u, err := strconv.ParseUint(strings.TrimSpace(tv), 0, 64)
		return err == nil && u == 0
	case []interface{}:
		for _, b := range tv {
			if !dpLimitValueIsZero(b) {
				return false
			}
		}
		return true
	}
	return false
}

// parseIngressPrioLayout 解析 `tc filter show dev <iface> ingress`, 验证:
//   - prio/pref 1 挂载了 bpf 打标程序
//   - prio/pref 2 挂载了 ifb0 mirred 重定向
func parseIngressPrioLayout(out string) (hasBPFPrio1 bool, hasIFBPrio2 bool) {
	curPrio := 0
	for _, ln := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "filter ") {
			curPrio = extractTCPrio(trimmed)
		}
		lower := strings.ToLower(trimmed)
		if curPrio == 1 && strings.Contains(lower, "bpf") {
			hasBPFPrio1 = true
		}
		if curPrio == 2 && (strings.Contains(lower, "ifb") || strings.Contains(lower, "mirred")) {
			hasIFBPrio2 = true
		}
	}
	return hasBPFPrio1, hasIFBPrio2
}

func extractTCPrio(line string) int {
	fs := strings.Fields(line)
	for i := 0; i+1 < len(fs); i++ {
		if fs[i] == "pref" || fs[i] == "prio" {
			n, err := strconv.Atoi(fs[i+1])
			if err == nil {
				return n
			}
		}
	}
	return 0
}

var (
	iptXMarkRE  = regexp.MustCompile(`--set-x?mark\s+(0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?`)
	iptNFMaskRE = regexp.MustCompile(`--(?:nfmask|ctmask)\s+(0x[0-9a-fA-F]+|\d+)`)
	tcFWLineRE  = regexp.MustCompile(`(?:\bfw\b[^\n]*?\bhandle\s+(0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?\s+(?:fw\s+)?(?:classid|flowid)\s+(\d+:[0-9a-fA-F]+)|\bhandle\s+(0x[0-9a-fA-F]+|\d+)(?:/(0x[0-9a-fA-F]+|\d+))?\s+fw\s+(?:classid|flowid)\s+(\d+:[0-9a-fA-F]+))`)
	tcFlowIDRE  = regexp.MustCompile(`(?:classid|flowid)\s+(\d+:[0-9a-fA-F]+)`)
)

func extractTCFWMatch(m []string) (handleStr, maskStr, classID string) {
	if len(m) >= 4 && m[1] != "" {
		return m[1], m[2], m[3]
	}
	if len(m) >= 7 && m[4] != "" {
		return m[4], m[5], m[6]
	}
	return "", "", ""
}

// checkNetdLow16Protection 校验 HNC 的 CONNMARK/MARK 规则是否严格限制在高 16 位 0xffff0000,
// 确保未污染低 16 位 0x0000ffff (Android netd netId / VPN 路由标记)。
func checkNetdLow16Protection(iptMangleV4, iptMangleV6, tcEgressFilters string) (string, bool) {
	checkRules := func(text string) bool {
		for _, ln := range strings.Split(text, "\n") {
			if !strings.Contains(ln, "HNC_") {
				continue
			}
			if m := iptXMarkRE.FindStringSubmatch(ln); len(m) >= 2 {
				val64, err1 := strconv.ParseUint(m[1], 0, 32)
				if err1 != nil {
					continue
				}
				var mask32 uint32 = uint32(0xffffffff)
				if len(m) >= 3 && m[2] != "" {
					m64, err2 := strconv.ParseUint(m[2], 0, 32)
					if err2 == nil {
						mask32 = uint32(m64)
					}
				}
				val32 := uint32(val64)
				if (mask32&dpNetdLow16Mask32) != 0 || (val32&dpNetdLow16Mask32) != 0 {
					return false
				}
			}
			if strings.Contains(ln, "--restore-mark") || strings.Contains(ln, "--save-mark") {
				matches := iptNFMaskRE.FindAllStringSubmatch(ln, -1)
				if len(matches) == 0 {
					return false // 未指定 nfmask/ctmask 默认是 0xffffffff, 会覆盖低 16 位 netd netId!
				}
				for _, mm := range matches {
					m64, err := strconv.ParseUint(mm[1], 0, 32)
					if err == nil && (uint32(m64)&dpNetdLow16Mask32) != 0 {
						return false
					}
				}
			}
		}
		return true
	}

	if !checkRules(iptMangleV4) || !checkRules(iptMangleV6) {
		return dpMarkLayoutLegacy, false
	}
	// 同时检查 tc fw 过滤器 handle 掩码是否触碰低 16 位
	for _, m := range tcFWLineRE.FindAllStringSubmatch(tcEgressFilters, -1) {
		hStr, maskStr, _ := extractTCFWMatch(m)
		if hStr == "" {
			continue
		}
		h64, err := strconv.ParseUint(hStr, 0, 32)
		if err == nil && (uint32(h64)&dpNetdLow16Mask32) != 0 {
			return dpMarkLayoutLegacy, false
		}
		if maskStr != "" {
			mask64, err2 := strconv.ParseUint(maskStr, 0, 32)
			if err2 == nil && (uint32(mask64)&dpNetdLow16Mask32) != 0 {
				return dpMarkLayoutLegacy, false
			}
		}
	}
	return dpMarkLayoutV540, true
}

func parseTCFWFilterHandles(tcOut string) map[string]uint32 {
	out := make(map[string]uint32)
	for _, m := range tcFWLineRE.FindAllStringSubmatch(tcOut, -1) {
		hStr, _, cid := extractTCFWMatch(m)
		if hStr == "" || cid == "" {
			continue
		}
		h64, err := strconv.ParseUint(hStr, 0, 32)
		if err == nil {
			out[normalizeTCClassID(cid)] = uint32(h64)
		}
	}
	return out
}

func parseTCFilterFlowIDs(tcOut string) map[string]bool {
	out := make(map[string]bool)
	for _, m := range tcFlowIDRE.FindAllStringSubmatch(tcOut, -1) {
		if len(m) >= 2 {
			out[normalizeTCClassID(m[1])] = true
		}
	}
	return out
}

func dpSlowpathActiveFromGuardMap(m map[string]interface{}) bool {
	if len(m) == 0 {
		return false
	}
	if dpJSONBool(m["slowpath_active"]) {
		return true
	}
	if rawSP, exists := m["slowpath"]; exists && rawSP != nil {
		switch v := rawSP.(type) {
		case string:
			sp := strings.ToLower(strings.TrimSpace(v))
			switch sp {
			case "":
				// fall through to fallback_active
			case "unavailable", "error", "false", "0", "off", "n/a", "empty":
				return false
			default:
				return dpParamTruthy(sp)
			}
		default:
			return dpJSONBool(rawSP)
		}
	}
	return dpJSONBool(m["fallback_active"]) || dpJSONBool(m["fallback"])
}

func dpInspectOffloadGuard(env *dpVerifyEnv) (DataplaneOffloadGuard, string) {
	m := dpReadJSONMap(env, filepath.Join(env.HNCDir, "run", "offload_guard.json"))
	mode := strings.ToLower(strings.TrimSpace(dpJSONString(m["mode"])))
	if mode == "" && env != nil && env.HNCDir != "" {
		if rm := dpReadJSONMap(env, filepath.Join(env.HNCDir, "data", "rules.json")); len(rm) > 0 {
			mode = clsactModeFromRules(rm)
		}
	}
	hwnat := strings.TrimSpace(dpJSONString(m["hwnat"]))
	if hwnat == "" {
		mtk := dpReadJSONMap(env, filepath.Join(env.HNCDir, "run", "mtk_hwnat.json"))
		hwnat = strings.TrimSpace(dpJSONString(mtk["action"]))
		if hwnat == "" {
			hwnat = strings.TrimSpace(dpJSONString(mtk["state"]))
		}
	}
	if hwnat == "" {
		hwnat = "none"
	}
	slowpath := dpSlowpathActiveFromGuardMap(m)
	tetherOff := dpJSONBool(m["tether_offload_disabled"])
	rawState := strings.ToUpper(strings.TrimSpace(dpJSONString(m["offload_state"])))
	return DataplaneOffloadGuard{
		Mode:                  mode,
		SlowpathActive:        slowpath,
		TetherOffloadDisabled: tetherOff,
		HWNAT:                 hwnat,
	}, rawState
}

func isIptChainIdentByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

func hasExactIptChainToken(s, chain string) bool {
	if s == "" || chain == "" {
		return false
	}
	for off := 0; off < len(s); {
		idx := strings.Index(s[off:], chain)
		if idx < 0 {
			return false
		}
		pos := off + idx
		end := pos + len(chain)
		leftOK := pos == 0 || !isIptChainIdentByte(s[pos-1])
		rightOK := end == len(s) || !isIptChainIdentByte(s[end])
		if leftOK && rightOK {
			return true
		}
		off = pos + 1
	}
	return false
}

func dpCheckIPv6QUICControlled(quicBlockCfg bool, iptFilterV6 string) bool {
	if iptFilterV6 == "" {
		return quicBlockCfg
	}
	hasGlobalChain := false
	hasPort443OutsideAppLim := false
	for _, line := range strings.Split(iptFilterV6, "\n") {
		if strings.Contains(line, "HNC_QUIC_APPLIM") {
			continue
		}
		if hasExactIptChainToken(line, "HNC_QUIC") {
			hasGlobalChain = true
		}
		if strings.Contains(line, "443") {
			hasPort443OutsideAppLim = true
		}
	}
	return hasGlobalChain && hasPort443OutsideAppLim
}

// ── 辅助映射与格式化纯函数 ────────────────────────────────────────────

func dpClassIDForMark(mid int) string {
	minor, err := htbClassMinorForMid(mid)
	if err != nil || minor == 0 {
		return ""
	}
	return formatTCHandle(rtnlHtbRootMaj | uint32(minor))
}

func dpMarkForDevice(mid int, classID string, fwFlowMap map[string]uint32) uint32 {
	if classID != "" {
		if liveMark, ok := fwFlowMap[classID]; ok && liveMark != 0 {
			return liveMark
		}
	}
	if mid < 1 || mid > 99 {
		return 0
	}
	// v5.40.0 正交高位编码: 0x00800000 | (mid << 16), 掩码 0x00ff0000, 严禁触碰低 16 位 netd netId
	return (dpV540DevMarkBase | (uint32(mid) << DefaultDevMarkShift)) & DefaultDevMarkMask
}

func dpLookupDeviceHTBStats(stats map[string]TCClassStats, classID string, mid int, includeAppQoSChildren bool) (TCClassStats, bool) {
	if classID == "" || len(stats) == 0 {
		return TCClassStats{}, false
	}
	st, ok := stats[classID]
	if !ok && mid >= 10 {
		// 兼容原生 Netlink 直接将十进制 mid 编入 uint16 minor 的情况(如 mid=12 -> 1:c)
		hexCID := fmt.Sprintf("1:%x", mid)
		st, ok = stats[hexCID]
	}
	if !ok {
		return TCClassStats{}, false
	}

	// 若设备开启了三档应用感知 QoS(1:a000 + mid*4 + 1..3), 聚合叶子子类丢包与超限计数防漏计
	if includeAppQoSChildren && mid > 0 {
		var childSent, childPkts, childDrops, childOverlimits uint64
		for tier := 1; tier <= 3; tier++ {
			cID := fmt.Sprintf("1:%x", dpAppQosMinorBase+mid*4+tier)
			if cst, cok := stats[cID]; cok {
				childSent += cst.SentBytes
				childPkts += cst.SentPkts
				childDrops += cst.Drops
				childOverlimits += cst.Overlimits
			}
		}
		if st.SentBytes == 0 && childSent > 0 {
			st.SentBytes = childSent
			st.SentPkts = childPkts
		}
		if childDrops > st.Drops {
			st.Drops = childDrops
		}
		if childOverlimits > st.Overlimits {
			st.Overlimits = childOverlimits
		}
	}
	return st, true
}

func formatDPBytesMB(b uint64) string {
	const mb = 1024.0 * 1024.0
	if b == 0 {
		return "0.00 MB"
	}
	val := float64(b) / mb
	if val < 0.01 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024.0)
	}
	return fmt.Sprintf("%.2f MB", val)
}

func dpReadJSONMap(env *dpVerifyEnv, path string) map[string]interface{} {
	if env == nil || env.ReadFile == nil {
		return map[string]interface{}{}
	}
	b, err := env.ReadFile(path)
	if err != nil || len(b) == 0 {
		return map[string]interface{}{}
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil || m == nil {
		return map[string]interface{}{}
	}
	return m
}

func dpReadAppLimits(env *dpVerifyEnv) []AppLimitItem {
	if env == nil || env.ReadFile == nil {
		return nil
	}
	b, err := env.ReadFile(filepath.Join(env.HNCDir, appLimitsJSONRelPath))
	if err != nil || len(b) == 0 {
		return nil
	}
	var f AppLimitFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Items
}

func dpLookupCaseInsensitiveObj(m map[string]interface{}, mac string) map[string]interface{} {
	if len(m) == 0 {
		return map[string]interface{}{}
	}
	if v, ok := m[mac].(map[string]interface{}); ok && v != nil {
		return v
	}
	upper := strings.ToUpper(mac)
	if v, ok := m[upper].(map[string]interface{}); ok && v != nil {
		return v
	}
	for k, raw := range m {
		if strings.EqualFold(k, mac) {
			if v, ok := raw.(map[string]interface{}); ok && v != nil {
				return v
			}
		}
	}
	return map[string]interface{}{}
}

func dpLookupDeviceName(namesMap, devObj map[string]interface{}, mac string) string {
	for _, key := range []string{mac, strings.ToUpper(mac)} {
		if nm := strings.TrimSpace(dpJSONString(namesMap[key])); nm != "" {
			return nm
		}
	}
	for k, v := range namesMap {
		if strings.EqualFold(k, mac) {
			if nm := strings.TrimSpace(dpJSONString(v)); nm != "" {
				return nm
			}
		}
	}
	for _, field := range []string{"name", "hostname", "vendor"} {
		nm := strings.TrimSpace(dpJSONString(devObj[field]))
		if nm != "" && !strings.EqualFold(nm, "null") && !strings.EqualFold(nm, "unknown") && nm != "*" {
			return nm
		}
	}
	return mac
}

func dpInferDeviceOnline(devObj map[string]interface{}, nowUnix int64) bool {
	if len(devObj) == 0 {
		return false
	}
	if v, ok := devObj["online"].(bool); ok {
		return v
	}
	if st := strings.ToUpper(strings.TrimSpace(dpJSONString(devObj["state"]))); st != "" {
		if st == "FAILED" || st == "OFFLINE" || st == "INCOMPLETE" {
			return false
		}
		if st == "REACHABLE" || st == "STALE" || st == "DELAY" || st == "ONLINE" {
			return true
		}
	}
	if ls := int64(dpJSONFloat(devObj["last_seen"])); ls > 0 && nowUnix > 0 {
		return (nowUnix - ls) <= 180
	}
	return strings.TrimSpace(dpJSONString(devObj["ip"])) != ""
}

func dpJSONBool(v interface{}) bool {
	switch tv := v.(type) {
	case bool:
		return tv
	case float64:
		return tv != 0
	case string:
		return dpParamTruthy(tv)
	}
	return false
}

func dpJSONFloat(v interface{}) float64 {
	switch tv := v.(type) {
	case json.Number:
		f, err := tv.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0
		}
		return f
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0
		}
		return tv
	case int:
		return float64(tv)
	case int64:
		return float64(tv)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(tv), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0
		}
		return f
	}
	return 0
}

func dpJSONUint64(v interface{}) uint64 {
	switch tv := v.(type) {
	case float64:
		if tv <= 0 || math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0
		}
		return uint64(tv)
	case uint64:
		return tv
	case int64:
		if tv <= 0 {
			return 0
		}
		return uint64(tv)
	case string:
		u, err := strconv.ParseUint(strings.TrimSpace(tv), 10, 64)
		if err != nil {
			return 0
		}
		return u
	}
	return 0
}

func dpJSONString(v interface{}) string {
	switch tv := v.(type) {
	case string:
		return tv
	case float64:
		return strconv.FormatFloat(tv, 'f', -1, 64)
	}
	return ""
}
