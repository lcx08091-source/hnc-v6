// selfcheck_api.go — v5.20 自检报告: HTTP 接口 / action / 缓存 / 导出 / 脱敏
//
// 数据模型与探测见 selfcheck.go。
//
//   GET /api/selfcheck[?redact=1]
//       → {available, running, schema, generated_at, generated_at_iso, version, duration_ms,
//          redacted, sections:[{id,title,elapsed_ms,items:[{id,label,status,value,detail?,fix?}]}],
//          summary:{ok,warn,fail,info}}
//       没有缓存时 {available:false, running}
//   action selfcheck_run    params: reprobe=1(先重跑 capability_probe.sh), redact=1
//       → detail = 报告 JSON(同上, 不含 available/running)
//   action selfcheck_export params: redact(默认 1; "0" 不脱敏), fresh=1(先重跑)
//       → detail = {"name","json_name","path","json_path","redacted","summary"}
//       文件写到 <HNC>/exports/, /api/exports 列出, 前端照诊断包的方式复制到 Download。
//
// 两个 action 都是只读诊断, 在 handleAction 里绕过 actionMu(见 dispatchSelfcheckAction),
// 自己用 selfcheckState.running 串行化(忙时直接报 busy, 不排队)。

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var selfcheckState struct {
	mu      sync.Mutex
	last    *scReport
	loaded  bool
	running sync.Mutex
	busy    bool
}

// selfcheckEnvFactory 测试替换点
var selfcheckEnvFactory = realSelfcheckEnv

const selfcheckExportKeep = 10

func selfcheckCachePath(hncDir string) string {
	return filepath.Join(hncDir, "run", "selfcheck.json")
}

// selfcheckCached 内存缓存; 首次访问读 run/selfcheck.json(httpd 重启后仍能看到上次结果)
func selfcheckCached(hncDir string) *scReport {
	selfcheckState.mu.Lock()
	defer selfcheckState.mu.Unlock()
	if selfcheckState.last == nil && !selfcheckState.loaded {
		selfcheckState.loaded = true
		if b, err := os.ReadFile(selfcheckCachePath(hncDir)); err == nil {
			var r scReport
			if json.Unmarshal(b, &r) == nil && r.GeneratedAt > 0 {
				selfcheckState.last = &r
			}
		}
	}
	return selfcheckState.last
}

func selfcheckIsRunning() bool {
	selfcheckState.mu.Lock()
	defer selfcheckState.mu.Unlock()
	return selfcheckState.busy
}

var errSelfcheckBusy = fmt.Errorf("selfcheck already running")

// selfcheckRun 跑一次并更新缓存(内存 + run/selfcheck.json, 0600: 含 MAC/IP)
func selfcheckRun(hncDir string, opts scOptions) (*scReport, error) {
	if !selfcheckState.running.TryLock() {
		return nil, errSelfcheckBusy
	}
	defer selfcheckState.running.Unlock()
	selfcheckState.mu.Lock()
	selfcheckState.busy = true
	selfcheckState.mu.Unlock()
	defer func() {
		selfcheckState.mu.Lock()
		selfcheckState.busy = false
		selfcheckState.mu.Unlock()
	}()

	rep := runSelfcheck(selfcheckEnvFactory(hncDir), opts)
	selfcheckState.mu.Lock()
	selfcheckState.last, selfcheckState.loaded = rep, true
	selfcheckState.mu.Unlock()
	if b, err := json.Marshal(rep); err == nil {
		_ = scWriteFile0600(selfcheckCachePath(hncDir), b)
	}
	return rep, nil
}

func scWriteFile0600(path string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

type scAPIResp struct {
	Available bool `json:"available"`
	Running   bool `json:"running"`
	*scReport
}

func (s *server) apiSelfcheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	setNoStore(w)
	rep := selfcheckCached(s.hncDir)
	if rep == nil {
		writeJSON(w, http.StatusOK, scAPIResp{Available: false, Running: selfcheckIsRunning()})
		return
	}
	if r.URL.Query().Get("redact") == "1" {
		rep = redactReport(rep)
	}
	writeJSON(w, http.StatusOK, scAPIResp{Available: true, Running: selfcheckIsRunning(), scReport: rep})
}

func scParamOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// dispatchSelfcheckAction 只读自检 action; handled=false 表示不是自检 action。
func dispatchSelfcheckAction(s *server, action string, p map[string]string) (actionResp, bool) {
	switch action {
	case "selfcheck_run":
		return actionSelfcheckRun(s.hncDir, p), true
	case "selfcheck_export":
		return actionSelfcheckExport(s.hncDir, p), true
	case "compat_report": // v5.29 T5: 兼容性报告(脱敏, 白名单收集)
		return actionCompatReport(s), true
	}
	return actionResp{}, false
}

func selfcheckActionStatus(r actionResp) int {
	switch {
	case r.OK:
		return http.StatusOK
	case r.Error == "busy":
		return http.StatusConflict
	case r.Error == "bad params":
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func actionSelfcheckRun(hncDir string, p map[string]string) actionResp {
	rep, err := selfcheckRun(hncDir, scOptions{Reprobe: scParamOn(p["reprobe"])})
	if err != nil {
		return actionResp{OK: false, Error: "busy", Detail: "自检正在进行, 请稍候"}
	}
	if scParamOn(p["redact"]) {
		rep = redactReport(rep)
	}
	b, _ := json.Marshal(rep)
	return actionResp{OK: true, Detail: string(b)}
}

func actionSelfcheckExport(hncDir string, p map[string]string) actionResp {
	redact := true
	if v, ok := p["redact"]; ok && strings.TrimSpace(v) != "" {
		redact = scParamOn(v)
	}
	rep := selfcheckCached(hncDir)
	if rep == nil || scParamOn(p["fresh"]) {
		var err error
		if rep, err = selfcheckRun(hncDir, scOptions{}); err != nil {
			return actionResp{OK: false, Error: "busy", Detail: "自检正在进行, 请稍候"}
		}
	}
	if redact {
		rep = redactReport(rep)
	}
	dir := filepath.Join(hncDir, "exports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	base := "hnc-selfcheck-" + time.Now().Format("20060102-150405")
	txtPath := filepath.Join(dir, base+".txt")
	jsonPath := filepath.Join(dir, base+".json")
	jb, _ := json.MarshalIndent(rep, "", "  ")
	if err := scWriteFile0600(jsonPath, jb); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	if err := scWriteFile0600(txtPath, []byte(renderSelfcheckText(rep))); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	// 前端用 shell cp 复制到 /sdcard/Download(以 root 运行, 0600 不影响); 远程走 /api/exports/<name>
	pruneSelfcheckExports(dir, selfcheckExportKeep)
	b, _ := json.Marshal(map[string]interface{}{
		"name": base + ".txt", "json_name": base + ".json",
		"path": txtPath, "json_path": jsonPath,
		"redacted": redact, "summary": rep.Summary,
	})
	return actionResp{OK: true, Detail: string(b)}
}

func isSelfcheckExport(n string) bool {
	return strings.HasPrefix(n, "hnc-selfcheck-") && (strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".json"))
}

// pruneSelfcheckExports 每种后缀只留最新 keep 份
func pruneSelfcheckExports(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	by := map[string][]string{}
	for _, e := range ents {
		n := e.Name()
		if isSelfcheckExport(n) {
			by[filepath.Ext(n)] = append(by[filepath.Ext(n)], n)
		}
	}
	for _, list := range by {
		sort.Strings(list) // 时间戳命名, 字典序即时间序
		for i := 0; i+keep < len(list); i++ {
			os.Remove(filepath.Join(dir, list[i]))
		}
	}
}

// ─── 文本报告 ────────────────────────────────────────────────────

func scMark(status string) string {
	switch status {
	case scOK:
		return "✓"
	case scWarn:
		return "!"
	case scFail:
		return "✗"
	}
	return "·"
}

// renderSelfcheckText 人读的中文报告, 每项一行
func renderSelfcheckText(r *scReport) string {
	var b strings.Builder
	b.WriteString("HNC 自检报告\n")
	ts := time.Unix(r.GeneratedAt, 0).Format("2006-01-02 15:04:05 -0700")
	fmt.Fprintf(&b, "版本: %s    生成时间: %s    耗时: %.1f 秒\n", r.Version, ts, float64(r.DurationMs)/1000)
	fmt.Fprintf(&b, "汇总: ✓ 正常 %d · ! 警告 %d · ✗ 失败 %d · · 信息 %d\n",
		r.Summary.OK, r.Summary.Warn, r.Summary.Fail, r.Summary.Info)
	if r.Redacted {
		b.WriteString("(已脱敏: MAC / IP 地址已打码)\n")
	}
	b.WriteString("图例: ✓ 正常  ! 警告  ✗ 失败  · 信息\n")
	for _, sec := range r.Sections {
		fmt.Fprintf(&b, "\n【%s】\n", sec.Title)
		for _, it := range sec.Items {
			line := fmt.Sprintf("%s %s: %s", scMark(it.Status), it.Label, it.Value)
			if it.Detail != "" {
				line += " — " + it.Detail
			}
			if it.Fix != "" {
				line += "  → 建议: " + it.Fix
			}
			b.WriteString(strings.ReplaceAll(line, "\n", " "))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// ─── 脱敏 ────────────────────────────────────────────────────────

var (
	scMACRE    = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	scMACIDRE  = regexp.MustCompile(`(?i)\bv6_dev_[0-9a-f]{12}\b`)
	scIP6RunRE = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	scIP4RE    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

// scRedactText 打码 MAC(保留末两字节便于对照) / IPv6(保留前 32 位) / IPv4(保留前两段)。
// 127.0.0.1 / ::1 / 0.0.0.0 等无隐私的地址保留。
func scRedactText(s string) string {
	s = scMACRE.ReplaceAllStringFunc(s, func(m string) string {
		return "xx:xx:xx:xx:" + strings.ToLower(m[12:14]+":"+m[15:17])
	})
	s = scMACIDRE.ReplaceAllStringFunc(s, func(m string) string {
		return "v6_dev_xxxxxxxx" + strings.ToLower(m[len(m)-4:])
	})
	s = scIP6RunRE.ReplaceAllStringFunc(s, func(m string) string {
		core := strings.TrimRight(m, ".")
		tail := m[len(core):]
		ip := net.ParseIP(core)
		if ip == nil || ip.To4() != nil || ip.IsLoopback() || ip.IsUnspecified() {
			return m
		}
		b := ip.To16()
		return fmt.Sprintf("%x:%x:*", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3])) + tail
	})
	s = scIP4RE.ReplaceAllStringFunc(s, func(m string) string {
		ip := net.ParseIP(m)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return m
		}
		p := strings.Split(m, ".")
		return p[0] + "." + p[1] + ".*.*"
	})
	return s
}

// redactReport 深拷贝后脱敏(缓存里的原件不动)
func redactReport(r *scReport) *scReport {
	if r == nil {
		return nil
	}
	out := *r
	out.Redacted = true
	out.Sections = make([]scSection, len(r.Sections))
	for i, sec := range r.Sections {
		ns := sec
		ns.Items = make([]scItem, len(sec.Items))
		for j, it := range sec.Items {
			ns.Items[j] = scItem{
				ID: scRedactText(it.ID), Label: scRedactText(it.Label), Status: it.Status,
				Value: scRedactText(it.Value), Detail: scRedactText(it.Detail), Fix: scRedactText(it.Fix),
			}
		}
		out.Sections[i] = ns
	}
	return &out
}
