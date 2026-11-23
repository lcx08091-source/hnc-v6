// phone_usage_sim.go — 双卡物理卡槽真值识别 + 默认路由出口(phone_usage.go / stats_calibration.go 共用)
//
// 权威双卡识别主链路(死定律八, 零 app_process 开销, 结果由 puEngine 缓存 5 分钟):
//  1. 优先调用原生 C++ Binder 服务 `dumpsys isub` + `dumpsys telephony.registry` 交叉验证:
//     - 解析 `Active modem count=N`(默认双卡上限夹紧在 [1, 2], 除非明确检测到三卡硬件属性);
//     - 按优先级 `activeDataSubId`(双卡智能切换/通话临时切卡真实流量卡) -> `defaultDataSubId`
//       -> `Logical SIM slot` / `telephony.registry` 连接态 -> 单卡在位唯一归属, 定位物理卡槽(1/2);
//     - 键名锚定边界提取字段, 剥离 imsi 尾部 [****] 脱敏掩码只取纯数字前缀;
//     - 五重过滤门禁剔除: simSlotIndex < 0 历史拔出卡、isOpportunistic、REMOTE_SIM、
//       云虚拟流量卡(逍遥游/ORoaming/红茶移动/天际通/小米全球上网/vsim 或伪 mcc=111/001)及超界槽位;
//     - 通过 MCC+MNC 与 normalizeCarrierAndMOCN 将英文运营商名统一归一化为标准中文名,
//       保证计费主键 `<slot>|<Carrier>` 稳定不分裂; 用户自定义卡名(USER_INPUT)独立输出到 custom_name。
//  2. 仅当 `dumpsys isub` 失败或无有效订阅时, 回退到保留 BOOTCLASSPATH / SYSTEMSERVERCLASSPATH /
//     ANDROID_* 环境变量的 `settings` + `content query --uri content://telephony/siminfo` + `getprop`。
//
// 全部失败 -> Slot=0, "蜂窝(未知卡)"。所有子进程均启用独立进程组 Setpgid + 超时向 -pgid 发 SIGKILL。

package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	puSafeAndroidPATH = "/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin"
	puIsubScanMaxBuf  = 1024 * 1024 // 1MB >= 512KB, 防 ColorOS/HyperOS 超长行截断
)

// puAndroidEnvAllowKeys 白名单透传 ART / Binder 包装脚本(content/settings/cmd/am)必需的运行环境变量。
var puAndroidEnvAllowKeys = []string{
	"BOOTCLASSPATH",
	"DEX2OATBOOTCLASSPATH",
	"SYSTEMSERVERCLASSPATH",
	"STANDALONE_SYSTEMSERVER_JARS",
	"ANDROID_ROOT",
	"ANDROID_DATA",
	"ANDROID_STORAGE",
	"ANDROID_ASSETS",
	"ANDROID_ART_ROOT",
	"ANDROID_I18N_ROOT",
	"ANDROID_TZDATA_ROOT",
	"TZ",
}

// puSanitizedAndroidEnv 构造带安全固定 PATH 并从当前进程透传 Android ART 运行时白名单变量的干净环境。
func puSanitizedAndroidEnv() []string {
	return puSanitizedAndroidEnvFrom(os.Environ())
}

func puSanitizedAndroidEnvFrom(rawEnv []string) []string {
	allow := make(map[string]bool, len(puAndroidEnvAllowKeys))
	for _, k := range puAndroidEnvAllowKeys {
		allow[k] = true
	}
	vals := make(map[string]string, len(puAndroidEnvAllowKeys))
	for _, kv := range rawEnv {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		k, v := kv[:eq], kv[eq+1:]
		if allow[k] && v != "" {
			if _, exists := vals[k]; !exists {
				vals[k] = v
			}
		}
	}
	out := make([]string, 0, 1+len(vals))
	out = append(out, "PATH="+puSafeAndroidPATH)
	for _, k := range puAndroidEnvAllowKeys {
		if v, ok := vals[k]; ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// puPrepareExecCmd 为外部命令统一挂载安全 Android 环境变量、Setpgid 进程组隔离、超时 -pgid SIGKILL 与 WaitDelay。
func puPrepareExecCmd(cmd *exec.Cmd) *exec.Cmd {
	cmd = hardenCmd(cmd)
	cmd.Env = puSanitizedAndroidEnv()
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return cmd.Process.Kill()
			}
			return nil
		}
	}
	cmd.WaitDelay = 400 * time.Millisecond
	return cmd
}

func puLookupSysBin(name string) (string, bool) {
	for _, d := range []string{"/system/bin/", "/system/xbin/", "/vendor/bin/"} {
		if st, err := os.Stat(d + name); err == nil && !st.IsDir() {
			return d + name, true
		}
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	return p, true
}

type puSIM struct {
	Slot       int    `json:"slot"` // 1/2, 0=未知
	Carrier    string `json:"carrier"`
	CustomName string `json:"custom_name,omitempty"`
	SubID      int    `json:"sub_id"`
	Source     string `json:"source"` // isub / registry / settings / getprop / ""
}

func (s puSIM) key() string {
	if s.Slot <= 0 {
		return "0|" + puUnknownSIM
	}
	c := strings.ReplaceAll(strings.TrimSpace(s.Carrier), "|", "/")
	if c == "" {
		c = "SIM" + strconv.Itoa(s.Slot)
	}
	return strconv.Itoa(s.Slot) + "|" + c
}

// puSIMProbe 汇总整机物理卡槽上限、全部在位物理卡与当前真实上网数据卡。
type puSIMProbe struct {
	Active     puSIM
	Slots      map[int]puSIM // 1-based slot -> puSIM
	SlotsKnown bool          // 是否成功枚举了整机在位物理卡集合
	MaxSlots   int           // 物理卡槽上限(默认夹紧在 [1, 2])
}

type puSubInfo struct {
	SubID       int
	SlotIndex   int // 0-based, -1 未插
	DisplayName string
	CarrierName string
}

// puRunCmd 跑一个系统命令, 5s 超时。name 先按常见绝对路径找, 再退 PATH。
func puRunCmd(name string, args ...string) (string, bool) {
	path, ok := puLookupSysBin(name)
	if !ok {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := puPrepareExecCmd(exec.CommandContext(ctx, path, args...))
	out, err := cmd.Output()
	if err != nil {
		return string(out), false
	}
	return string(out), true
}

// puRunDumpsysHead 流式读取 dumpsys 输出头部(512KB+ 缓冲), 遇到 local logs: 或行数上限立即截断并结束子进程。
func puRunDumpsysHead(timeout time.Duration, maxLines int, service string) (string, bool) {
	path, ok := puLookupSysBin("dumpsys")
	if !ok {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := puPrepareExecCmd(exec.CommandContext(ctx, path, service))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", false
	}
	if err := cmd.Start(); err != nil {
		return "", false
	}
	var sb strings.Builder
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), puIsubScanMaxBuf)
	lines := 0
	truncated := false
	for sc.Scan() {
		line := sc.Text()
		if puIsLocalLogsHeader(line) || (maxLines > 0 && lines >= maxLines) {
			truncated = true
			break
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		lines++
	}
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancel()
	waitErr := cmd.Wait()
	if !truncated && (timedOut || waitErr != nil) && sb.Len() == 0 {
		return "", false
	}
	return sb.String(), sb.Len() > 0
}

func puIsLocalLogsHeader(line string) bool {
	low := strings.ToLower(strings.TrimSpace(line))
	return strings.HasPrefix(low, "local logs:") ||
		strings.HasPrefix(low, "subscriptionmanagerservice local logs") ||
		strings.HasPrefix(low, "subscriptioncontroller:") && strings.Contains(low, "local logs")
}

// puParseSubID "1\n" -> 1; "null"/空/非正数 -> 0
func puParseSubID(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

var (
	puIsubRE            = regexp.MustCompile(`(?i)\b(?:mDefaultDataSubId|default\s*data\s*sub(?:scription)?\s*id)\s*[=:]\s*(-?\d+)`)
	puIsubActiveDataRE  = regexp.MustCompile(`(?i)\b(?:mActiveDataSubId|active\s*data\s*sub(?:scription)?\s*id)\s*[=:]\s*(-?\d+)`)
	puIsubModemCountRE  = regexp.MustCompile(`(?i)\b(?:active\s*modem\s*count|mActiveModemCount|activeModemCount)\s*[=:]\s*(\d+)`)
	puIsubLogicalSlotRE = regexp.MustCompile(`(?i)logical\s+sim\s+slot\s+(\d+)\s*:\s*subId\s*[=:]\s*(-?\d+)`)
	puIsubSlotMapRE     = regexp.MustCompile(`(?i)mSimSlotIndexToSubId\s*=\s*\{([^}]*)\}`)
	puIsubSlotPairRE    = regexp.MustCompile(`(\d+)\s*=\s*\[?\s*(-?\d+)`)
	puIsubTripleSimRE   = regexp.MustCompile(`(?i)(?:multisim\.config\s*=\s*tsts|triple[_\s]*sim\s*[=:]\s*true)`)
	puIsubKeyAnchorRE   = regexp.MustCompile(`(?:^|,\s*|\s+|[\[{])([A-Za-z_][A-Za-z0-9_]*)=`)
	puRegPhoneBlockRE   = regexp.MustCompile(`^\s*Phone Id\s*=\s*(\d+)`)
	puRegSubIDRE        = regexp.MustCompile(`\bmSubId\s*=\s*(-?\d+)`)
	puRegDataConnRE     = regexp.MustCompile(`\bmDataConnectionState\s*=\s*(\d+)`)
)

func puParseIsubDefaultData(out string) int {
	m := puIsubRE.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	return puParseSubID(m[1])
}

// puIsubEntry 表示通过五重门禁后的单张真实在位物理 SIM 卡订阅信息。
type puIsubEntry struct {
	SubID             int
	Slot              int    // 1-based 物理卡槽(simSlotIndex + 1)
	SlotIndex         int    // 0-based 物理卡槽
	Carrier           string // 归一化标准中文运营商名(如 "中国联通", "中国移动")
	CustomName        string // 用户自定义名称(USER_INPUT 且与标准运营商名不同时非空)
	RawCarrierName    string
	RawDisplayName    string
	DisplayNameSource string
	MCC               string
	MNC               string
	IMSI              string // 剥离 [****] 掩码后的纯数字前缀
	IccID             string
	CardString        string
}

// puIsubSnapshot 表示原生 `dumpsys isub` 解析快照。
type puIsubSnapshot struct {
	MaxSlots         int                 // 物理卡槽上限(默认夹紧在 [1, 2], 明确三卡硬件时为 3)
	ModemCount       int                 // Active modem count 原始值(0=未出现)
	ActiveDataSubID  int                 // activeDataSubId (最高优先级)
	DefaultDataSubID int                 // defaultDataSubId
	LogicalSlotSubID map[int]int         // 0-based logical slot -> subId
	Subs             []puIsubEntry       // 在位物理卡列表(按 Slot 升序)
	BySlot           map[int]puIsubEntry // 1-based slot -> puIsubEntry
	BySubID          map[int]puIsubEntry // subId -> puIsubEntry
}

func puCleanSimField(s string) string {
	v := strings.TrimSpace(s)
	if v == "" || strings.EqualFold(v, "null") || strings.EqualFold(v, "unknown") || v == "----" {
		return ""
	}
	return v
}

// puCleanIMSI 剥离 `460011898[****]` 或 `460011...` 尾部的脱敏掩码, 仅保留开头的连续纯数字前缀。
func puCleanIMSI(raw string) string {
	s := puCleanSimField(raw)
	if s == "" {
		return ""
	}
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end < 5 {
		return ""
	}
	return s[:end]
}

func puCleanMCCMNC(mccRaw, mncRaw, mccmncRaw, imsiPrefix string) (string, string) {
	digitsOnly := func(s string) string {
		s = puCleanSimField(s)
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return ""
			}
		}
		return s
	}
	mcc := digitsOnly(mccRaw)
	if mcc == "0" || len(mcc) != 3 {
		mcc = ""
	}
	mnc := digitsOnly(mncRaw)
	if mcc == "" {
		mnc = ""
	} else if len(mnc) == 1 {
		mnc = "0" + mnc
	} else if len(mnc) > 3 {
		mnc = ""
	}
	comb := digitsOnly(mccmncRaw)
	if len(comb) >= 5 && len(comb) <= 6 {
		if mcc == "" {
			mcc = comb[:3]
		}
		if mnc == "" {
			mnc = comb[3:]
		}
	}
	if mcc == "" && len(imsiPrefix) >= 5 && imsiPrefix[:3] == "460" {
		mcc = "460"
		mnc = imsiPrefix[3:5]
	}
	return mcc, mnc
}

func puIsUserDisplayNameSource(src string) bool {
	s := strings.ToUpper(strings.TrimSpace(src))
	return s == "2" || strings.Contains(s, "USER_INPUT")
}

func puIsOpportunisticVal(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "true" || s == "1"
}

func puIsRemoteSubType(v string) bool {
	s := strings.ToUpper(strings.TrimSpace(v))
	return s == "1" || strings.Contains(s, "REMOTE")
}

var puCloudSimKeywords = []string{
	"oroaming",
	"逍遥游",
	"redtea",
	"红茶移动",
	"小米全球上网",
	"virtualsim",
	"vsim",
	"skytone",
	"天际通",
}

func puIsCloudVirtualSim(mcc, imsi string, fields ...string) bool {
	if mcc == "111" || mcc == "001" || strings.HasPrefix(imsi, "111") || strings.HasPrefix(imsi, "001") {
		return true
	}
	joined := strings.ToLower(strings.Join(fields, " | "))
	for _, kw := range puCloudSimKeywords {
		if strings.Contains(joined, kw) {
			return true
		}
	}
	return false
}

// puNormalizeIsubCarrier 通过 MCC+MNC 与 normalizeCarrierAndMOCN 归一化标准运营商名, 并分离用户自定义卡名。
func puNormalizeIsubCarrier(slot int, mcc, mnc, carrierName, displayName, displayNameSource string) (carrier, customName string) {
	plmn := ""
	if len(mcc) == 3 && len(mnc) >= 2 {
		plmn = mcc + mnc
	}
	cClean := puCleanSimField(carrierName)
	dClean := puCleanSimField(displayName)
	isUser := puIsUserDisplayNameSource(displayNameSource)

	if isUser {
		carrier, _, _ = normalizeCarrierAndMOCN(cClean, "", plmn, "", "")
		if carrier == "" && dClean != "" {
			carrier = dClean
		}
	} else {
		carrier, _, _ = normalizeCarrierAndMOCN(cClean, dClean, plmn, "", "")
	}
	if carrier == "" {
		if cClean != "" {
			carrier = cClean
		} else if dClean != "" {
			carrier = dClean
		} else if slot > 0 {
			carrier = "SIM" + strconv.Itoa(slot)
		}
	}
	if isUser && dClean != "" && dClean != carrier {
		customName = dClean
	}
	return carrier, customName
}

// puTrimUnbalancedRight 剥离字段值末尾不属于自身配对括号(如 imsi=46001[****] 内部配对括号保留)的外层闭合符。
func puTrimUnbalancedRight(s string) string {
	s = strings.TrimSpace(s)
	for len(s) > 0 {
		last := s[len(s)-1]
		switch last {
		case ',', ';':
			s = strings.TrimSpace(s[:len(s)-1])
		case ']':
			if strings.Count(s, "]") > strings.Count(s, "[") {
				s = strings.TrimSpace(s[:len(s)-1])
			} else {
				return s
			}
		case '}':
			if strings.Count(s, "}") > strings.Count(s, "{") {
				s = strings.TrimSpace(s[:len(s)-1])
			} else {
				return s
			}
		default:
			return s
		}
	}
	return s
}

// puParseIsubKV 使用“键名锚定边界”解析单条 SubscriptionInfoInternal / SubscriptionInfo 行,
// 严禁按空格切分以免截断 `China Unicom`、`中国移动 — giffgaff` 或 `联通, 副卡`。
func puParseIsubKV(line string) map[string]string {
	s := strings.TrimSpace(line)
	if idx := strings.Index(s, "[SubscriptionInfoInternal:"); idx >= 0 {
		s = s[idx+len("[SubscriptionInfoInternal:"):]
	} else if idx := strings.Index(s, "[SubscriptionInfo:"); idx >= 0 {
		s = s[idx+len("[SubscriptionInfo:"):]
	} else if idx := strings.IndexByte(s, '{'); idx >= 0 {
		s = s[idx+1:]
	} else {
		return nil
	}
	s = strings.TrimSpace(s)
	matches := puIsubKeyAnchorRE.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return nil
	}
	kv := make(map[string]string, len(matches))
	for i, loc := range matches {
		key := s[loc[2]:loc[3]]
		valStart := loc[1]
		valEnd := len(s)
		if i+1 < len(matches) {
			valEnd = matches[i+1][0]
		}
		val := puTrimUnbalancedRight(s[valStart:valEnd])
		if prev, exists := kv[key]; !exists || (prev == "" && val != "") {
			kv[key] = val
		}
	}
	if _, hasID := kv["id"]; !hasID {
		if _, hasSubID := kv["subId"]; !hasSubID {
			return nil
		}
	}
	if _, hasSlot := kv["simSlotIndex"]; !hasSlot {
		if _, hasMSlot := kv["mSimSlotIndex"]; !hasMSlot {
			return nil
		}
	}
	return kv
}

func puFirstNonEmpty(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// puParseIsubDump 解析 Android 12~16 原生 / ColorOS / HyperOS 的 `dumpsys isub` 输出。
func puParseIsubDump(raw string) puIsubSnapshot {
	snap := puIsubSnapshot{
		MaxSlots:         2,
		LogicalSlotSubID: map[int]int{},
		BySlot:           map[int]puIsubEntry{},
		BySubID:          map[int]puIsubEntry{},
	}
	if strings.TrimSpace(raw) == "" {
		return snap
	}
	tripleHW := puIsubTripleSimRE.MatchString(raw)

	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), puIsubScanMaxBuf)

	var mergedByID map[int]map[string]string
	var idOrder []int
	mergeRec := func(kv map[string]string) {
		idStr := puFirstNonEmpty(kv, "id", "subId", "mId")
		id, err := strconv.Atoi(idStr)
		if err != nil || id <= 0 {
			return
		}
		if mergedByID == nil {
			mergedByID = map[int]map[string]string{}
		}
		dst, exists := mergedByID[id]
		if !exists {
			dst = make(map[string]string, len(kv))
			mergedByID[id] = dst
			idOrder = append(idOrder, id)
		}
		for k, v := range kv {
			if prev := puCleanSimField(dst[k]); prev == "" && puCleanSimField(v) != "" {
				dst[k] = v
			} else if _, ok := dst[k]; !ok {
				dst[k] = v
			}
		}
	}

	var pendingSub strings.Builder
	pendingLines := 0
	flushPending := func() {
		if pendingSub.Len() > 0 {
			if kv := puParseIsubKV(pendingSub.String()); kv != nil {
				mergeRec(kv)
			}
			pendingSub.Reset()
			pendingLines = 0
		}
	}

	for sc.Scan() {
		line := sc.Text()
		if puIsLocalLogsHeader(line) {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flushPending()
			continue
		}
		isSubStart := strings.Contains(trimmed, "[SubscriptionInfoInternal:") ||
			strings.Contains(trimmed, "[SubscriptionInfo:")
		if pendingSub.Len() > 0 {
			if isSubStart {
				flushPending()
			} else {
				pendingSub.WriteByte(' ')
				pendingSub.WriteString(trimmed)
				pendingLines++
				if strings.HasSuffix(trimmed, "]") || pendingLines >= 8 {
					flushPending()
				}
				continue
			}
		}
		if isSubStart {
			pendingSub.WriteString(trimmed)
			pendingLines = 1
			if strings.HasSuffix(trimmed, "]") {
				flushPending()
			}
			continue
		}
		if strings.Contains(trimmed, "simSlotIndex=") && strings.Contains(trimmed, "id=") && strings.Contains(trimmed, "{") {
			if kv := puParseIsubKV(trimmed); kv != nil {
				mergeRec(kv)
				continue
			}
		}

		if snap.ModemCount == 0 {
			if m := puIsubModemCountRE.FindStringSubmatch(trimmed); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
					snap.ModemCount = n
				}
			}
		}
		if snap.ActiveDataSubID == 0 {
			if m := puIsubActiveDataRE.FindStringSubmatch(trimmed); m != nil {
				if id := puParseSubID(m[1]); id > 0 {
					snap.ActiveDataSubID = id
				}
			}
		}
		if snap.DefaultDataSubID == 0 {
			if m := puIsubRE.FindStringSubmatch(trimmed); m != nil {
				if id := puParseSubID(m[1]); id > 0 {
					snap.DefaultDataSubID = id
				}
			}
		}
		if m := puIsubLogicalSlotRE.FindStringSubmatch(trimmed); m != nil {
			slotIdx, e1 := strconv.Atoi(m[1])
			subID, e2 := strconv.Atoi(m[2])
			if e1 == nil && e2 == nil && slotIdx >= 0 && subID > 0 {
				snap.LogicalSlotSubID[slotIdx] = subID
			}
		}
		if m := puIsubSlotMapRE.FindStringSubmatch(trimmed); m != nil {
			for _, pm := range puIsubSlotPairRE.FindAllStringSubmatch(m[1], -1) {
				slotIdx, e1 := strconv.Atoi(pm[1])
				subID, e2 := strconv.Atoi(pm[2])
				if e1 == nil && e2 == nil && slotIdx >= 0 && subID > 0 {
					if _, exists := snap.LogicalSlotSubID[slotIdx]; !exists {
						snap.LogicalSlotSubID[slotIdx] = subID
					}
				}
			}
		}
	}
	flushPending()

	// 计算物理卡槽上限: 默认双卡夹紧在 [1, 2], 除非明确检测到三卡硬件属性
	switch {
	case snap.ModemCount == 1:
		snap.MaxSlots = 1
	case tripleHW && snap.ModemCount >= 3:
		snap.MaxSlots = 3
	default:
		snap.MaxSlots = 2
	}

	entryBetter := func(cand, cur puIsubEntry) bool {
		if wantSub, ok := snap.LogicalSlotSubID[cand.SlotIndex]; ok && wantSub > 0 {
			if cand.SubID == wantSub && cur.SubID != wantSub {
				return true
			}
			if cur.SubID == wantSub && cand.SubID != wantSub {
				return false
			}
		}
		if cand.SubID == snap.ActiveDataSubID && cur.SubID != snap.ActiveDataSubID {
			return true
		}
		if cur.SubID == snap.ActiveDataSubID && cand.SubID != snap.ActiveDataSubID {
			return false
		}
		return cand.SubID > cur.SubID
	}

	for _, id := range idOrder {
		kv := mergedByID[id]
		slotStr := puFirstNonEmpty(kv, "simSlotIndex", "mSimSlotIndex", "slotIndex")
		slotIdx, err := strconv.Atoi(slotStr)
		if err != nil {
			continue
		}
		// 门禁 1: 剔除历史拔出残留卡(simSlotIndex < 0)
		if slotIdx < 0 {
			continue
		}
		// 门禁 2: 剔除 opportunistic 临时/伴随虚拟订阅
		if puIsOpportunisticVal(puFirstNonEmpty(kv, "isOpportunistic", "mIsOpportunistic")) {
			continue
		}
		// 门禁 3: 剔除 REMOTE_SIM 远程卡
		if puIsRemoteSubType(puFirstNonEmpty(kv, "subscriptionType", "mSubscriptionType")) {
			continue
		}
		imsi := puCleanIMSI(puFirstNonEmpty(kv, "imsi", "mImsi"))
		mcc, mnc := puCleanMCCMNC(
			puFirstNonEmpty(kv, "mcc", "mcc_string", "mMcc"),
			puFirstNonEmpty(kv, "mnc", "mnc_string", "mMnc"),
			puFirstNonEmpty(kv, "mccmnc", "mMccmnc"),
			imsi,
		)
		rawCarrier := puCleanSimField(puFirstNonEmpty(kv, "carrierName", "mCarrierName"))
		rawDisplay := puCleanSimField(puFirstNonEmpty(kv, "displayName", "mDisplayName"))
		cardStr := puCleanSimField(puFirstNonEmpty(kv, "cardString", "mCardString"))
		iccID := puCleanSimField(puFirstNonEmpty(kv, "iccId", "mIccId"))
		groupOwner := puCleanSimField(puFirstNonEmpty(kv, "groupOwner", "mGroupOwner"))
		// 门禁 4: 剔除云虚拟流量卡特征或伪 MCC(111/001)
		if puIsCloudVirtualSim(mcc, imsi, rawCarrier, rawDisplay, cardStr, iccID, groupOwner) {
			continue
		}
		// 门禁 5: 严格限制在真实物理卡槽 [1, MaxSlots]
		slot := slotIdx + 1
		if slot < 1 || slot > snap.MaxSlots {
			continue
		}
		nameSrc := puCleanSimField(puFirstNonEmpty(kv, "displayNameSource", "mDisplayNameSource", "nameSource"))
		carrier, customName := puNormalizeIsubCarrier(slot, mcc, mnc, rawCarrier, rawDisplay, nameSrc)
		entry := puIsubEntry{
			SubID:             id,
			Slot:              slot,
			SlotIndex:         slotIdx,
			Carrier:           carrier,
			CustomName:        customName,
			RawCarrierName:    rawCarrier,
			RawDisplayName:    rawDisplay,
			DisplayNameSource: nameSrc,
			MCC:               mcc,
			MNC:               mnc,
			IMSI:              imsi,
			IccID:             iccID,
			CardString:        cardStr,
		}
		if prev, exists := snap.BySlot[slot]; !exists || entryBetter(entry, prev) {
			if exists {
				delete(snap.BySubID, prev.SubID)
			}
			snap.BySlot[slot] = entry
			snap.BySubID[entry.SubID] = entry
		}
	}

	if len(snap.BySlot) > 0 {
		slots := make([]int, 0, len(snap.BySlot))
		for s := range snap.BySlot {
			slots = append(slots, s)
		}
		sort.Ints(slots)
		snap.Subs = make([]puIsubEntry, 0, len(slots))
		for _, s := range slots {
			snap.Subs = append(snap.Subs, snap.BySlot[s])
		}
	}
	return snap
}

type puRegistryPhoneState struct {
	PhoneID       int
	SubID         int
	DataConnected bool
}

type puRegistryDataState struct {
	ActiveDataSubID int
	Phones          map[int]puRegistryPhoneState // PhoneID (0-based) -> state
}

// puParseRegistryDataState 从 `dumpsys telephony.registry` 头部提取 mActiveDataSubId 与各物理卡槽蜂窝连接态。
func puParseRegistryDataState(raw string) puRegistryDataState {
	st := puRegistryDataState{Phones: map[int]puRegistryPhoneState{}}
	if strings.TrimSpace(raw) == "" {
		return st
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), puIsubScanMaxBuf)
	curPhone := -1
	for sc.Scan() {
		line := sc.Text()
		if puIsLocalLogsHeader(line) {
			break
		}
		if st.ActiveDataSubID == 0 {
			if m := puIsubActiveDataRE.FindStringSubmatch(line); m != nil {
				if id := puParseSubID(m[1]); id > 0 {
					st.ActiveDataSubID = id
				}
			}
		}
		if m := puRegPhoneBlockRE.FindStringSubmatch(line); m != nil {
			pid, err := strconv.Atoi(m[1])
			if err == nil && pid >= 0 {
				curPhone = pid
				if _, ok := st.Phones[pid]; !ok {
					st.Phones[pid] = puRegistryPhoneState{PhoneID: pid}
				}
			}
			continue
		}
		if curPhone < 0 {
			continue
		}
		ps := st.Phones[curPhone]
		if ps.SubID == 0 {
			if m := puRegSubIDRE.FindStringSubmatch(line); m != nil {
				if id := puParseSubID(m[1]); id > 0 {
					ps.SubID = id
				}
			}
		}
		if m := puRegDataConnRE.FindStringSubmatch(line); m != nil && m[1] == "2" {
			ps.DataConnected = true
		}
		st.Phones[curPhone] = ps
	}
	return st
}

// puResolveProbeFromIsub 结合 `dumpsys isub` 与 `telephony.registry` 交叉验证确定当前真实上网物理卡槽。
func puResolveProbeFromIsub(isub puIsubSnapshot, reg puRegistryDataState) (puSIMProbe, bool) {
	if len(isub.Subs) == 0 {
		return puSIMProbe{MaxSlots: isub.MaxSlots}, false
	}
	probe := puSIMProbe{
		Slots:      make(map[int]puSIM, len(isub.Subs)),
		SlotsKnown: true,
		MaxSlots:   isub.MaxSlots,
	}
	toSIM := func(e puIsubEntry, src string) puSIM {
		return puSIM{
			Slot:       e.Slot,
			Carrier:    e.Carrier,
			CustomName: e.CustomName,
			SubID:      e.SubID,
			Source:     src,
		}
	}
	for _, e := range isub.Subs {
		probe.Slots[e.Slot] = toSIM(e, "isub")
	}

	pickBySubID := func(subID int, src string) (puSIM, bool) {
		if subID <= 0 {
			return puSIM{}, false
		}
		if e, ok := isub.BySubID[subID]; ok {
			return toSIM(e, src), true
		}
		for slotIdx, sid := range isub.LogicalSlotSubID {
			if sid == subID {
				if e, ok := isub.BySlot[slotIdx+1]; ok {
					s := toSIM(e, src)
					s.SubID = subID
					return s, true
				}
			}
		}
		return puSIM{}, false
	}

	isSlotDataConnected := func(slot int) bool {
		ps, ok := reg.Phones[slot-1]
		return ok && ps.DataConnected
	}

	// 1. 最高优先级: activeDataSubId (双卡智能切换/通话临时上网的真实当前流量卡)
	if reg.ActiveDataSubID > 0 && reg.ActiveDataSubID != isub.ActiveDataSubID {
		if regSim, ok := pickBySubID(reg.ActiveDataSubID, "isub"); ok {
			isubSim, hasIsubActive := pickBySubID(isub.ActiveDataSubID, "isub")
			if !hasIsubActive || (isSlotDataConnected(regSim.Slot) && !isSlotDataConnected(isubSim.Slot)) {
				probe.Active = regSim
				return probe, true
			}
		}
	}
	if s, ok := pickBySubID(isub.ActiveDataSubID, "isub"); ok {
		probe.Active = s
		return probe, true
	}
	if s, ok := pickBySubID(reg.ActiveDataSubID, "isub"); ok {
		probe.Active = s
		return probe, true
	}

	// 2. 次高优先级: defaultDataSubId
	if s, ok := pickBySubID(isub.DefaultDataSubID, "isub"); ok {
		probe.Active = s
		return probe, true
	}

	// 3. telephony.registry 唯一处于 DATA_CONNECTED(2) 的在位物理槽
	connSlot := 0
	for _, e := range isub.Subs {
		if isSlotDataConnected(e.Slot) {
			if connSlot != 0 {
				connSlot = -1
				break
			}
			connSlot = e.Slot
		}
	}
	if connSlot > 0 {
		probe.Active = toSIM(isub.BySlot[connSlot], "registry")
		return probe, true
	}

	// 4. 整机仅插有唯一 1 张真实物理卡: 蜂窝流量物理上只能走该卡
	if len(isub.Subs) == 1 {
		probe.Active = toSIM(isub.Subs[0], "isub")
		return probe, true
	}

	probe.Active = puSIM{Slot: 0, Carrier: puUnknownSIM}
	return probe, true
}

var puKVStartRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// puParseContentRow 解析 `content query` 的一行:
// "Row: 0 _id=1, sim_id=0, display_name=中国移动, carrier_name=CMCC, x"
// 值里可能含 ", ", 所以按 ", " 切开后把不像 "key=" 开头的片段拼回上一个值。
func puParseContentRow(line string) map[string]string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "Row:") {
		return nil
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "Row:"))
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[i+1:] // 去掉行号
	} else {
		return nil
	}
	out := map[string]string{}
	last := ""
	for _, part := range strings.Split(rest, ", ") {
		if puKVStartRE.MatchString(part) {
			eq := strings.IndexByte(part, '=')
			last = part[:eq]
			out[last] = part[eq+1:]
		} else if last != "" {
			out[last] += ", " + part
		}
	}
	return out
}

func puParseSiminfo(out string) []puSubInfo {
	var subs []puSubInfo
	for _, line := range strings.Split(out, "\n") {
		kv := puParseContentRow(line)
		if kv == nil {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv["_id"]))
		if err != nil {
			continue
		}
		slot := -1
		if v, err := strconv.Atoi(strings.TrimSpace(kv["sim_id"])); err == nil {
			slot = v
		}
		clean := func(s string) string {
			s = strings.TrimSpace(s)
			if s == "NULL" || s == "null" {
				return ""
			}
			return s
		}
		subs = append(subs, puSubInfo{SubID: id, SlotIndex: slot,
			DisplayName: clean(kv["display_name"]), CarrierName: clean(kv["carrier_name"])})
	}
	return subs
}

// puParseAlpha "中国移动,中国联通" -> ["中国移动","中国联通"]
func puParseAlpha(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// puResolveSIM 纯函数(兼容 content query 回退链路与既有单测): 各数据源 -> 默认数据卡
func puResolveSIM(subID int, source string, subs []puSubInfo, alpha []string) puSIM {
	alphaAt := func(slot int) string {
		if slot >= 1 && slot <= len(alpha) {
			return alpha[slot-1]
		}
		return ""
	}
	if subID > 0 {
		for _, s := range subs {
			if s.SubID == subID && s.SlotIndex >= 0 && s.SlotIndex < 2 {
				slot := s.SlotIndex + 1
				name := s.DisplayName
				if name == "" {
					name = alphaAt(slot)
				}
				if name == "" {
					name = s.CarrierName
				}
				return puSIM{Slot: slot, Carrier: name, SubID: subID, Source: source}
			}
		}
	}
	// 只有一张物理卡槽有运营商名 -> 数据只能走它
	only := 0
	limit := len(alpha)
	if limit > 2 {
		limit = 2
	}
	for i := 0; i < limit; i++ {
		if alpha[i] != "" {
			if only != 0 {
				only = -1
				break
			}
			only = i + 1
		}
	}
	if only > 0 {
		return puSIM{Slot: only, Carrier: alpha[only-1], SubID: subID, Source: "getprop"}
	}
	return puSIM{Slot: 0, Carrier: puUnknownSIM, SubID: subID}
}

// puDetectSIMProbeWith 可注入命令执行器的完整探测流程:
// 优先走原生 `dumpsys isub` + `telephony.registry` 交叉验证; 仅当失败或无有效在位订阅时才回退 `content query`。
func puDetectSIMProbeWith(run func(name string, args ...string) (string, bool)) puSIMProbe {
	var isubSnap puIsubSnapshot
	if out, ok := run("dumpsys", "isub"); ok && strings.TrimSpace(out) != "" {
		isubSnap = puParseIsubDump(out)
		if len(isubSnap.Subs) > 0 {
			var reg puRegistryDataState
			if regOut, rok := run("dumpsys", "telephony.registry"); rok && regOut != "" {
				reg = puParseRegistryDataState(regOut)
			}
			if probe, resolved := puResolveProbeFromIsub(isubSnap, reg); resolved {
				return probe
			}
		}
	}

	// 回退链路: 带 BOOTCLASSPATH 的 settings + content query + getprop
	maxSlots := isubSnap.MaxSlots
	if maxSlots <= 0 {
		maxSlots = 2
	}
	subID, source := 0, ""
	if isubSnap.ActiveDataSubID > 0 {
		subID, source = isubSnap.ActiveDataSubID, "isub"
	} else if isubSnap.DefaultDataSubID > 0 {
		subID, source = isubSnap.DefaultDataSubID, "isub"
	}
	if subID == 0 {
		if out, ok := run("settings", "get", "global", "multi_sim_data_call"); ok {
			if subID = puParseSubID(out); subID > 0 {
				source = "settings"
			}
		}
	}
	var subs []puSubInfo
	slots := map[int]puSIM{}
	slotsKnown := false
	if out, ok := run("content", "query", "--uri", "content://telephony/siminfo"); ok && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(out, "\n") {
			kv := puParseContentRow(line)
			if kv == nil {
				continue
			}
			id, err := strconv.Atoi(strings.TrimSpace(kv["_id"]))
			if err != nil {
				continue
			}
			slotIdx := -1
			if v, err := strconv.Atoi(strings.TrimSpace(kv["sim_id"])); err == nil {
				slotIdx = v
			}
			if slotIdx < 0 || slotIdx >= maxSlots {
				continue
			}
			if puIsOpportunisticVal(kv["is_opportunistic"]) || puIsRemoteSubType(kv["subscription_type"]) {
				continue
			}
			imsi := puCleanIMSI(kv["imsi"])
			mcc, mnc := puCleanMCCMNC(kv["mcc_string"], kv["mnc_string"], "", imsi)
			if mcc == "" {
				mcc, mnc = puCleanMCCMNC(kv["mcc"], kv["mnc"], "", imsi)
			}
			rawCarrier := puCleanSimField(kv["carrier_name"])
			rawDisplay := puCleanSimField(kv["display_name"])
			if puIsCloudVirtualSim(mcc, imsi, rawCarrier, rawDisplay, kv["card_id"], kv["icc_id"]) {
				continue
			}
			nameSrc := puCleanSimField(puFirstNonEmpty(kv, "name_source", "display_name_source"))
			slot := slotIdx + 1
			carrier, customName := puNormalizeIsubCarrier(slot, mcc, mnc, rawCarrier, rawDisplay, nameSrc)
			slotsKnown = true
			subs = append(subs, puSubInfo{SubID: id, SlotIndex: slotIdx, DisplayName: carrier, CarrierName: carrier})
			slots[slot] = puSIM{Slot: slot, Carrier: carrier, CustomName: customName, SubID: id, Source: "siminfo"}
		}
	}
	var alpha []string
	if out, ok := run("getprop", "gsm.sim.operator.alpha"); ok {
		alpha = puParseAlpha(out)
	}
	active := puResolveSIM(subID, source, subs, alpha)
	if active.Slot == 0 && slotsKnown && len(slots) == 1 {
		for _, onlySim := range slots {
			active = onlySim
		}
	} else if s, ok := slots[active.Slot]; ok && active.CustomName == "" {
		active.CustomName = s.CustomName
	}
	return puSIMProbe{
		Active:     active,
		Slots:      slots,
		SlotsKnown: slotsKnown,
		MaxSlots:   maxSlots,
	}
}

// puDetectSIMProbe 真机完整双卡探测(流式截断 local logs, 零 app_process 优先)。
func puDetectSIMProbe() puSIMProbe {
	return puDetectSIMProbeWith(func(name string, args ...string) (string, bool) {
		if name == "dumpsys" && len(args) == 1 && (args[0] == "isub" || args[0] == "telephony.registry") {
			return puRunDumpsysHead(4*time.Second, 3000, args[0])
		}
		return puRunCmd(name, args...)
	})
}

// puDetectSIM 真机探测默认/当前数据卡(由引擎缓存 5 分钟)
func puDetectSIM() puSIM {
	return puDetectSIMProbe().Active
}

var puRouteDevRE = regexp.MustCompile(`\bdev\s+(\S+)`)

func puParseRouteGet(out string) string {
	m := puRouteDevRE.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

// puDefaultRouteIface `ip route get 1.1.1.1` 的出口口名。root 进程不带 fwmark,
// 命中 netd 的"默认网络"规则, 即系统当前默认网络(Wi-Fi 或数据卡)。
func puDefaultRouteIface() string {
	out, ok := puRunCmd("ip", "route", "get", "1.1.1.1")
	if !ok {
		return ""
	}
	return puParseRouteGet(out)
}
