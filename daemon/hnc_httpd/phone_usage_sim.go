// phone_usage_sim.go — 默认数据卡识别 + 默认路由出口(phone_usage.go 用)
//
// 默认数据卡(按可靠性依次尝试, 结果由 puEngine 缓存 5 分钟):
//  1. subId: `settings get global multi_sim_data_call`(AOSP 多卡默认数据 subId,
//     ColorOS 同样维护); 拿不到/非正数再试 `dumpsys isub` 里的
//     "defaultDataSubId=N"(Android 13+ SubscriptionManagerService 的 dump 格式)。
//  2. subId → 卡槽/运营商: `content query --uri content://telephony/siminfo`
//     取 _id / sim_id(卡槽下标, -1=未插) / display_name / carrier_name。
//     root 调用 content 命令不受 READ_PHONE_STATE 约束。
//  3. 运营商名兜底: `getprop gsm.sim.operator.alpha`(逗号分隔, 按卡槽顺序)。
//     siminfo 查不到时, 若只有一张卡有名字 → 数据只能走这张卡, 直接归它。
//
// 全部失败 → Slot=0, "蜂窝(未知卡)"。命令都走绝对路径优先(运行期 /system/bin
// 可能被 Magic Mount 卸掉, 见 CLAUDE.md), 5 秒超时 + hardenCmd。

package main

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type puSIM struct {
	Slot    int    `json:"slot"` // 1/2, 0=未知
	Carrier string `json:"carrier"`
	SubID   int    `json:"sub_id"`
	Source  string `json:"source"` // settings / isub / getprop / ""
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

type puSubInfo struct {
	SubID       int
	SlotIndex   int // 0-based, -1 未插
	DisplayName string
	CarrierName string
}

// puRunCmd 跑一个系统命令, 5s 超时。name 先按常见绝对路径找, 再退 PATH。
func puRunCmd(name string, args ...string) (string, bool) {
	path := ""
	for _, d := range []string{"/system/bin/", "/system/xbin/", "/vendor/bin/"} {
		if st, err := os.Stat(d + name); err == nil && !st.IsDir() {
			path = d + name
			break
		}
	}
	if path == "" {
		p, err := exec.LookPath(name)
		if err != nil {
			return "", false
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, path, args...))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
	out, err := cmd.Output()
	if err != nil {
		return string(out), false
	}
	return string(out), true
}

// puParseSubID "1\n" → 1; "null"/空/非正数 → 0
func puParseSubID(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

var puIsubRE = regexp.MustCompile(`(?i)default\s*data\s*sub(?:scription)?\s*id\s*[=:]\s*(-?\d+)`)

func puParseIsubDefaultData(out string) int {
	m := puIsubRE.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	return puParseSubID(m[1])
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

// puParseAlpha "中国移动,中国联通" → ["中国移动","中国联通"]
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

// puResolveSIM 纯函数: 各数据源 → 默认数据卡
func puResolveSIM(subID int, source string, subs []puSubInfo, alpha []string) puSIM {
	alphaAt := func(slot int) string {
		if slot >= 1 && slot <= len(alpha) {
			return alpha[slot-1]
		}
		return ""
	}
	if subID > 0 {
		for _, s := range subs {
			if s.SubID == subID && s.SlotIndex >= 0 {
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
	// 只有一张卡有运营商名 → 数据只能走它
	only := 0
	for i, a := range alpha {
		if a != "" {
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

// puDetectSIM 真机探测(有 exec, 由引擎缓存 5 分钟)
func puDetectSIM() puSIM {
	subID, source := 0, ""
	if out, ok := puRunCmd("settings", "get", "global", "multi_sim_data_call"); ok {
		if subID = puParseSubID(out); subID > 0 {
			source = "settings"
		}
	}
	if subID == 0 {
		if out, ok := puRunCmd("dumpsys", "isub"); ok {
			if subID = puParseIsubDefaultData(out); subID > 0 {
				source = "isub"
			}
		}
	}
	var subs []puSubInfo
	if subID > 0 {
		if out, ok := puRunCmd("content", "query", "--uri", "content://telephony/siminfo",
			"--projection", "_id:sim_id:display_name:carrier_name"); ok {
			subs = puParseSiminfo(out)
		}
	}
	var alpha []string
	if out, ok := puRunCmd("getprop", "gsm.sim.operator.alpha"); ok {
		alpha = puParseAlpha(out)
	}
	return puResolveSIM(subID, source, subs, alpha)
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
