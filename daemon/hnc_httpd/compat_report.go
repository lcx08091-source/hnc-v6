// compat_report.go — v5.29 T5: 一键导出本机兼容性报告(脱敏)。
//
// action compat_report → 写 exports/hnc-compat-YYYYMMDD.json, /api/exports
// 列出, 前端照自检报告的方式下载/复制到 Download。
//
// 内容(全部为「排查不同 ROM 兼容性」所需, 白名单式收集):
//   - 模块版本(version/versionCode, module.prop)
//   - Android 版本 / 品牌 / 型号(getprop, 通用机型名不含个人信息)
//   - 内核版本(/proc/version 第一行)
//   - root 方案(scCtx.detectRoot 的 Impls / Label, 识别方式与自检同一套)
//   - run/capabilities.json、run/qdisc_caps.json(能力布尔, 整段转出)
//   - offload 兜底状态(run/offload_guard.json 的 mode/state/fallback 三键)
//   - dpid 守护选择(run/dpid_launcher.choice)
//   - 自检各段汇总: 只有 {段 ID, 项目 ID, 状态} 与 ok/warn/fail/info 计数
//     —— 不含任何具体值(自检 value/detail 里可能有 SSID 等)
//   - 看门狗动作记账摘要(run/watchdog_actions.json: 每动作 calls_1h/
//     fails_1h/last_rc, 不含 stdout)
//
// 脱敏(硬约束, 测试断言): 不含 MAC、IP、SSID、热点密码、设备名、
// 序列号、IMEI、任何 token。实现方式是白名单字段收集 —— 任何含敏感值
// 的文件都只取指定键 / 只取结构, 永不整段转出(devices.json / rules.json
// 一律不读)。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// compatReport 导出文件结构。
type compatReport struct {
	Schema          int                    `json:"schema"`
	GeneratedAt     int64                  `json:"generated_at"`
	Module          compatModule           `json:"module"`
	Android         compatAndroid          `json:"android"`
	Root            map[string]interface{} `json:"root"`
	Caps            json.RawMessage        `json:"capabilities,omitempty"`
	QdiscCaps       json.RawMessage        `json:"qdisc_caps,omitempty"`
	Offload         map[string]interface{} `json:"offload_guard,omitempty"`
	DpidChoice      string                 `json:"dpid_launcher,omitempty"`
	Selfcheck       compatScSummary        `json:"selfcheck"`
	WatchdogActions map[string]interface{} `json:"watchdog_actions,omitempty"`
}

type compatModule struct {
	Version     string `json:"version"`
	VersionCode string `json:"version_code"`
}

type compatAndroid struct {
	Version string `json:"version,omitempty"`
	Brand   string `json:"brand,omitempty"`
	Model   string `json:"model,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
}

type compatScSummary struct {
	Ok       int               `json:"ok"`
	Warn     int               `json:"warn"`
	Fail     int               `json:"fail"`
	Info     int               `json:"info"`
	Sections []compatScSection `json:"sections"`
}

type compatScSection struct {
	ID    string         `json:"id"`
	Title string         `json:"title"`
	Items []compatScItem `json:"items"`
}

type compatScItem struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// 机型名的合法字符(防 getprop 输出被塞私货进报告)
var compatSafeText = regexp.MustCompile(`^[A-Za-z0-9 ._()+/-]{1,64}$`)

func compatClean(s string) string {
	s = strings.TrimSpace(s)
	if !compatSafeText.MatchString(s) {
		return ""
	}
	return s
}

// readCompatRawJSON 读一个 run/ 下的 JSON 文件做整段转出(仅限无敏感值的
// 能力文件; 其他文件一律不走这里)。
func readCompatRawJSON(path string) json.RawMessage {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	var v interface{}
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	// 递归删除任何疑似键(纵深防御: capabilities 理论上只有布尔/字符串枚举)
	scrubSensitive(v)
	out, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return json.RawMessage(out)
}

var sensitiveKeyPat = regexp.MustCompile(`(?i)mac|passwd|password|passphrase|ssid|token|secret|imei|serial|device_name|devname|label|ip_addr|ipaddr`)

// scrubSensitive 递归删敏感键(map 原地删; 返回是否删过)。
func scrubSensitive(v interface{}) bool {
	switch m := v.(type) {
	case map[string]interface{}:
		for k, val := range m {
			if sensitiveKeyPat.MatchString(k) {
				delete(m, k)
				continue
			}
			scrubSensitive(val)
		}
		return true
	case []interface{}:
		for _, val := range m {
			scrubSensitive(val)
		}
		return true
	}
	return false
}

// readCompatKV 从 JSON 文件取白名单键。
func readCompatKV(path string, keys ...string) map[string]interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	out := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch v.(type) {
			case string, float64, bool, nil:
				out[k] = v
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildCompatReport 组装报告(所有数据源见文件头注释)。
func buildCompatReport(hncDir string, c *scCtx) *compatReport {
	rep := &compatReport{
		Schema:      1,
		GeneratedAt: time.Now().Unix(),
	}
	// 模块版本: 编译期注入的 version / versionCode(build.sh 从 module.prop
	// 读)。运行目录里并没有 module.prop(post-fs-data / service.sh 都不拷它,
	// rc1 只读那里, 真机上恒为空); 只有开发构建(version=dev)才回退去读。
	if version != "dev" {
		rep.Module = compatModule{Version: compatClean(version), VersionCode: compatClean(versionCode)}
	} else if b, err := os.ReadFile(filepath.Join(hncDir, "module.prop")); err == nil {
		rep.Module = compatModule{Version: compatClean(propLine(string(b), "version")), VersionCode: compatClean(propLine(string(b), "versionCode"))}
	}
	// Android: getprop 三键 + 内核(/proc/version 首行)
	rep.Android = compatAndroid{
		Version: compatClean(c.prop("ro.build.version.release")),
		Brand:   compatClean(c.prop("ro.product.brand")),
		Model:   compatClean(c.prop("ro.product.model")),
	}
	if b, err := os.ReadFile("/proc/version"); err == nil {
		if line, _, _ := strings.Cut(string(b), "\n"); line != "" {
			// 只留 "Linux version X.Y.Z-..." — 括号里是编译机用户@主机,
			// 兼容排查用不上还带环境信息, 一并去掉。
			if base, _, ok := strings.Cut(line, " ("); ok {
				line = base
			}
			rep.Android.Kernel = compatClean(line)
		}
	}
	// root 方案(与自检同一套识别)
	if r := c.detectRoot(); len(r.Impls) > 0 {
		rep.Root = map[string]interface{}{"impls": r.Impls, "label": compatClean(r.Label)}
	}
	rep.Caps = readCompatRawJSON(filepath.Join(hncDir, "run", "capabilities.json"))
	rep.QdiscCaps = readCompatRawJSON(filepath.Join(hncDir, "run", "qdisc_caps.json"))
	// offload 兜底: 只取三键(state 文本可能带 iface 名, 属于通用网卡名)
	rep.Offload = readCompatKV(filepath.Join(hncDir, "run", "offload_guard.json"), "mode", "state", "fallback")
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "dpid_launcher.choice")); err == nil {
		if v := compatClean(strings.TrimSpace(string(b))); v != "" {
			rep.DpidChoice = v
		}
	}
	// 自检: 只取 段ID/项ID/状态 + 计数
	if sc := selfcheckCached(hncDir); sc != nil {
		s := compatScSummary{Ok: sc.Summary.OK, Warn: sc.Summary.Warn, Fail: sc.Summary.Fail, Info: sc.Summary.Info}
		for _, sec := range sc.Sections {
			cs := compatScSection{ID: sec.ID, Title: compatClean(sec.Title)}
			for _, it := range sec.Items {
				cs.Items = append(cs.Items, compatScItem{ID: it.ID, Status: string(it.Status)})
			}
			s.Sections = append(s.Sections, cs)
		}
		rep.Selfcheck = s
	}
	// 看门狗动作记账: 每动作 calls_1h/fails_1h/last_rc
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "watchdog_actions.json")); err == nil {
		var m struct {
			Actions map[string]map[string]interface{} `json:"actions"`
		}
		if json.Unmarshal(b, &m) == nil && len(m.Actions) > 0 {
			sum := make(map[string]interface{}, len(m.Actions))
			for name, a := range m.Actions {
				if !compatNameOK(name) {
					continue
				}
				item := map[string]interface{}{}
				for _, k := range []string{"calls_1h", "fails_1h", "last_rc"} {
					if v, ok := a[k].(float64); ok {
						item[k] = v
					}
				}
				if len(item) > 0 {
					sum[name] = item
				}
			}
			if len(sum) > 0 {
				rep.WatchdogActions = sum
			}
		}
	}
	return rep
}

var compatNameRe = regexp.MustCompile(`^[a-z0-9_.-]{1,48}$`)

func compatNameOK(name string) bool { return compatNameRe.MatchString(name) }

func propLine(body, key string) string {
	for _, ln := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(ln, key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// actionCompatReport action 入口(挂在 dispatchSelfcheckAction)。
func actionCompatReport(s *server) actionResp {
	// scCtx.run 要 ctx(selfcheckRun 从请求 ctx 传入; 这里是后台生成, 用 Background)
	c := &scCtx{env: selfcheckEnvFactory(s.hncDir), ctx: context.Background()}
	rep := buildCompatReport(s.hncDir, c)
	dir := filepath.Join(s.hncDir, "exports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	name := "hnc-compat-" + time.Now().Format("20060102") + ".json"
	path := filepath.Join(dir, name)
	b, _ := json.MarshalIndent(rep, "", "  ")
	if err := scWriteFile0600(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf(`{"name":%q,"path":%q,"summary":{"ok":%d,"warn":%d,"fail":%d}}`,
		name, path, rep.Selfcheck.Ok, rep.Selfcheck.Warn, rep.Selfcheck.Fail)}
}

// isCompatExport /api/exports 的导出白名单。
func isCompatExport(n string) bool {
	ok, _ := regexp.MatchString(`^hnc-compat-\d{8}\.json$`, n)
	return ok
}

// dispatchCompatReport 供 dispatchSelfcheckAction 调用。
func dispatchCompatReport(s *server, action string, p map[string]string) (actionResp, bool) {
	if action != "compat_report" {
		return actionResp{}, false
	}
	_ = p
	return actionCompatReport(s), true
}
