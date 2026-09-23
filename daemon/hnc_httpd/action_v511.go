// action_v511.go — v5.11 新 WebUI(v6) 前后端对齐补齐的动作与只读接口。
//
// 旧前端有一批功能直接 ksu.exec 跑 shell 改状态(QoS 策略、模板落盘、清缓存、
// 诊断包、DPI 规则库、运行状态面板), 绕过 httpd 的写锁与审计, 且远程浏览器
// 里完全不可用。这里把它们全部收口成 /api/action 动作或只读 GET, 新前端
// 本机/远程走同一套接口。

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ── 白名单 ────────────────────────────────────────────────────

// syncWhitelist 让 rules.json 的白名单状态落到 iptables(bin/whitelist_sync.sh)。
func syncWhitelist(hncDir string, prev actionResp) actionResp {
	rc, out := runBin(hncDir, "whitelist_sync.sh")
	out = strings.TrimSpace(out)
	if rc != 0 {
		return actionResp{OK: false, Error: "whitelist sync failed", Detail: lastLine(out)}
	}
	if d := lastLine(out); d != "" {
		prev.Detail = d
	}
	return prev
}

func actionDeviceWhitelistSet(hncDir string, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	v := p["enabled"]
	if v != "true" && v != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	rc, out := runBin(hncDir, "json_set.sh", "device", mac, "whitelist", v)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
	}
	return syncWhitelist(hncDir, actionResp{OK: true})
}

// ── QoS 策略(仅 root HTB 兼容链路时生效, 见 tc_manager.sh qos_*) ──

func actionQosSet(hncDir string, p map[string]string) actionResp {
	mode, hasMode := p["mode"]
	scale, hasScale := p["scale"]
	if !hasMode && !hasScale {
		return actionResp{OK: false, Error: "bad params", Detail: "mode or scale required"}
	}
	run := filepath.Join(hncDir, "run")
	if hasMode {
		if mode != "precise" && mode != "compat" {
			return actionResp{OK: false, Error: "bad params", Detail: "mode must be precise/compat"}
		}
		if err := writeFileAtomic(filepath.Join(run, "tc_qos_mode"), []byte(mode+"\n")); err != nil {
			return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
		}
		if rc, out := runBin(hncDir, "json_set.sh", "top", "tc_qos_mode", mode); rc != 0 {
			return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
		}
	}
	if hasScale {
		n, err := strconv.Atoi(strings.TrimSpace(scale))
		if err != nil || n < 50 || n > 120 {
			return actionResp{OK: false, Error: "bad params", Detail: "scale must be 50-120"}
		}
		if err := writeFileAtomic(filepath.Join(run, "tc_qos_scale"), []byte(strconv.Itoa(n)+"\n")); err != nil {
			return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
		}
		if rc, out := runBin(hncDir, "json_set.sh", "top", "tc_qos_scale", strconv.Itoa(n)); rc != 0 {
			return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
		}
	}
	return actionResp{OK: true, Detail: "applies on next rule apply"}
}

// ── 模板(templates.json; 旧前端 shell 调 json_set.sh tpl_set/tpl_del) ──

func validTemplateName(n string) bool {
	if n == "" || !utf8.ValidString(n) || utf8.RuneCountInString(n) > 32 {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func tplNum(s string, max float64) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "0", true
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > max {
		return "", false
	}
	return strconv.FormatFloat(v, 'f', -1, 64), true
}

func actionTemplateSet(hncDir string, p map[string]string) actionResp {
	name := strings.TrimSpace(p["name"])
	if !validTemplateName(name) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid template name"}
	}
	args := []string{"tpl_set", name}
	for _, f := range []struct {
		k   string
		max float64
	}{{"down_mbps", 10240}, {"up_mbps", 10240}, {"delay_ms", 10000}, {"jitter_ms", 5000}, {"loss_pct", 100}} {
		v, ok := tplNum(p[f.k], f.max)
		if !ok {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid " + f.k}
		}
		args = append(args, v)
	}
	rc, out := runBin(hncDir, "json_set.sh", args...)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true}
}

func actionTemplateDel(hncDir string, p map[string]string) actionResp {
	name := strings.TrimSpace(p["name"])
	if !validTemplateName(name) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid template name"}
	}
	rc, out := runBin(hncDir, "json_set.sh", "tpl_del", name)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true}
}

// ── 维护 ──────────────────────────────────────────────────────

func actionCacheClear(hncDir string) actionResp {
	n := 0
	for _, f := range []string{"hostname_cache", "dev_class_cache"} {
		if err := os.Remove(filepath.Join(hncDir, "cache", f)); err == nil {
			n++
		}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("removed %d file(s)", n)}
}

// actionDebugBundle 把诊断包生成到 exports/ (与 /api/exports 同目录),
// 本机前端再复制到 /sdcard/Download, 远程浏览器走 /api/exports/<name> 下载。
func actionDebugBundle(hncDir string) actionResp {
	dir := filepath.Join(hncDir, "exports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	rc, out := runBin(hncDir, "debug_bundle.sh", dir)
	path := lastLine(strings.TrimSpace(out))
	if rc != 0 || path == "" {
		return actionResp{OK: false, Error: "debug bundle failed", Detail: lastLine(out)}
	}
	name := filepath.Base(path)
	if filepath.Dir(path) != dir || !strings.HasSuffix(name, ".tar.gz") {
		return actionResp{OK: false, Error: "debug bundle failed", Detail: "tar unavailable, bundle left as directory: " + path}
	}
	b, _ := json.Marshal(map[string]string{"name": name, "path": path})
	return actionResp{OK: true, Detail: string(b)}
}

// ── DPI 规则库 ────────────────────────────────────────────────

func actionDPIRulesReset(hncDir string) actionResp {
	rc, out := runBin(hncDir, "dpi_rules_import.sh", "--reset")
	if rc != 0 {
		return actionResp{OK: false, Error: "reset failed", Detail: lastLine(out)}
	}
	return actionResp{OK: true, Detail: lastLine(out)}
}

func actionDPIRulesUpdate(hncDir string, p map[string]string) actionResp {
	flag := map[string]string{"check": "--check", "install": "--install"}[p["mode"]]
	if flag == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be check/install"}
	}
	rc, out := runBin(hncDir, "dpi_rules_update.sh", flag)
	out = strings.TrimSpace(out)
	if rc != 0 {
		return actionResp{OK: false, Error: "update failed", Detail: lastLine(out)}
	}
	// --check 输出 JSON; 若混有日志行, 取最后一个 JSON 对象
	if flag == "--check" {
		if i := strings.LastIndex(out, "{"); i >= 0 && json.Valid([]byte(out[i:])) {
			out = out[i:]
		}
	}
	return actionResp{OK: true, Detail: out}
}

// GET /api/dpi_rules → 当前生效的自定义规则库; POST {rules:"<json>"} → 导入(≤512KB)
func (s *server) apiDPIRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rc, out := runBin(s.hncDir, "dpi_rules_import.sh", "--export")
		if rc != 0 || !json.Valid([]byte(out)) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "export failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "rules": out, "source": "dpi_rules_import.sh --export"})
		return
	}
	s.requireMutationN(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rules string `json:"rules"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "bad json"})
			return
		}
		body := []byte(strings.TrimSpace(req.Rules))
		if len(body) == 0 || len(body) > 512*1024 || !json.Valid(body) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "rules must be valid JSON ≤512KB"})
			return
		}
		var probe struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if json.Unmarshal(body, &probe) != nil || probe.Rules == nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "missing top-level rules array"})
			return
		}
		tmp := filepath.Join(s.hncDir, "run", fmt.Sprintf("dpi_rules_upload.%d.json", time.Now().UnixNano()))
		if err := os.WriteFile(tmp, body, 0600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "write failed"})
			return
		}
		defer os.Remove(tmp)
		s.actionMu.Lock()
		rc, out := runBin(s.hncDir, "dpi_rules_import.sh", tmp)
		s.actionMu.Unlock()
		auditLog(s.hncDir, writeRateKey(r), "dpi_rules_import", map[string]string{"bytes": strconv.Itoa(len(body))}, map[bool]string{true: "ok", false: "error"}[rc == 0], lastLine(out))
		if rc != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "import failed", "detail": lastLine(out)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "detail": lastLine(out)})
	}, 600*1024)(w, r)
}

// ── 只读: 规则导出 / 运行状态 / 进程健康 ─────────────────────

// GET /api/rules_export → rules.json + templates.json(热点密码脱敏)
func (s *server) apiRulesExport(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(filepath.Join(s.hncDir, "data", "rules.json"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rules.json unreadable"})
		return
	}
	var rules map[string]interface{}
	if json.Unmarshal(b, &rules) != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rules.json invalid"})
		return
	}
	for k := range rules {
		if sensitiveKeys[strings.ToLower(k)] || k == "hotspot_pass" {
			rules[k] = "<redacted>"
		}
	}
	var tpl interface{} = map[string]interface{}{}
	if tb, err := os.ReadFile(filepath.Join(s.hncDir, "data", "templates.json")); err == nil {
		_ = json.Unmarshal(tb, &tpl)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules, "templates": tpl, "exported_at": time.Now().Unix()})
}

// runStatusScript 只含常量, 不拼接任何请求参数。
const runStatusScript = `IF=$(sed -n 's/^ACTIVE://p' "$HNC_DIR/run/hnc_state" 2>/dev/null | head -1)
[ -n "$IF" ] || IF=$(head -1 "$HNC_DIR/run/iface.cache" 2>/dev/null)
HP=$(pidof hotspotd 2>/dev/null | awk '{print $1}')
[ -n "$HP" ] || HP=$(cat "$HNC_DIR/run/hotspotd.pid" 2>/dev/null)
if [ -n "$HP" ] && [ -d "/proc/$HP" ]; then echo HOTSPOTD=up; echo HPID=$HP; echo HRSS=$(awk '/VmRSS/{print $2}' /proc/$HP/status 2>/dev/null); else echo HOTSPOTD=down; fi
T=0; if [ -n "$IF" ]; then T=$( { tc qdisc show dev "$IF"; tc class show dev "$IF"; tc qdisc show dev ifb0; tc class show dev ifb0; } 2>/dev/null | wc -l); fi; echo TC=$T
echo IPT=$(iptables -t mangle -S 2>/dev/null | grep -c 0x800000)
echo WD=$(ps -ef 2>/dev/null | grep -c '[h]nc_watchdog\|[w]atchdog.sh')
echo IFACE=$IF`

func (s *server) apiRunStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, "sh", "-c", runStatusScript))
	cmd.Env = []string{"HNC_DIR=" + s.hncDir, "PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin"}
	out, _ := cmd.Output()
	kv := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		if i := strings.IndexByte(ln, '='); i > 0 {
			kv[ln[:i]] = strings.TrimSpace(ln[i+1:])
		}
	}
	atoi := func(k string) int { n, _ := strconv.Atoi(kv[k]); return n }
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hotspotd":        map[bool]string{true: "up", false: "down"}[kv["HOTSPOTD"] == "up"],
		"hotspotd_pid":    atoi("HPID"),
		"hotspotd_rss_kb": atoi("HRSS"),
		"tc_rules":        atoi("TC"),
		"ipt_rules":       atoi("IPT"),
		"watchdog":        atoi("WD"),
		"iface":           kv["IFACE"],
	})
}

// GET /api/proc_health → bin/rc17_process_health.sh 的 JSON 原样透传
func (s *server) apiProcHealth(w http.ResponseWriter, r *http.Request) {
	rc, out := runBin(s.hncDir, "rc17_process_health.sh")
	out = strings.TrimSpace(out)
	if i := strings.Index(out, "{"); i > 0 {
		out = out[i:]
	}
	if rc != 0 || !json.Valid([]byte(out)) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "process health unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(out))
}

// ── 小工具 ────────────────────────────────────────────────────

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func writeFileAtomic(path string, b []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
