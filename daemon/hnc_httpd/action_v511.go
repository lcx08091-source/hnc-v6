// action_v511.go — v5.11 新 WebUI(v6) 前后端对齐补齐的动作与只读接口。
//
// 旧前端有一批功能直接 ksu.exec 跑 shell 改状态(QoS 策略、模板落盘、清缓存、
// 诊断包、DPI 规则库、运行状态面板), 绕过 httpd 的写锁与审计, 且远程浏览器
// 里完全不可用。这里把它们全部收口成 /api/action 动作或只读 GET, 新前端
// 本机/远程走同一套接口。

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"hnc.io/dpid/nlroute"
	"hnc.io/dpid/procfind" // v5.26 T3: 进程检测唯一权威
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
	if err := rulesStore.SetWhitelist(hncDir, mac, v == "true"); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(err.Error())}
	}
	rulesStore.Invalidate(hncDir)
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
		if err := rulesStore.SetTop(hncDir, "tc_qos_mode", mode); err != nil {
			return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(err.Error())}
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
		if err := rulesStore.SetTop(hncDir, "tc_qos_scale", n); err != nil {
			return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(err.Error())}
		}
	}
	rulesStore.Invalidate(hncDir)
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
	invalidateJSONCaches(filepath.Join(hncDir, "data", "templates.json"))
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
	invalidateJSONCaches(filepath.Join(hncDir, "data", "templates.json"))
	return actionResp{OK: true}
}

// ── 维护 ──────────────────────────────────────────────────────

const orphanTmpMinAge = 10 * time.Minute

func isOrphanTmpFileName(name string) bool {
	if name == "" {
		return false
	}
	return strings.HasSuffix(name, ".tmp") ||
		strings.Contains(name, ".tmp.") ||
		strings.Contains(name, ".tmp_") ||
		strings.Contains(name, ".tmp-")
}

func isProtectedRunSelfFile(name string) bool {
	switch name {
	case "self_capture.enabled", "self_attrib.enabled", "self_studio.poke", "self_runtime.json":
		return true
	}
	return strings.HasSuffix(name, ".enabled") ||
		strings.HasSuffix(name, ".poke") ||
		strings.HasSuffix(name, ".pid") ||
		strings.HasSuffix(name, ".lock")
}

func actionCacheClear(hncDir string) actionResp {
	n := 0
	for _, f := range []string{"hostname_cache", "dev_class_cache"} {
		if err := os.Remove(filepath.Join(hncDir, "cache", f)); err == nil {
			n++
		}
	}
	// 仅清理 mtime 早于 10 分钟前的陈旧孤儿 *.tmp* 文件, 严禁误删在途原子写盘临时文件
	cutoff := time.Now().Add(-orphanTmpMinAge)
	tmpDirs := []string{
		filepath.Join(hncDir, "run"),
		filepath.Join(hncDir, "data"),
		filepath.Join(hncDir, "data", "self_studio"),
		filepath.Join(hncDir, "data", "dpi_history"),
	}
	for _, dir := range tmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if isOrphanTmpFileName(name) {
				info, ierr := e.Info()
				if ierr != nil || !info.ModTime().Before(cutoff) {
					continue
				}
				if os.Remove(filepath.Join(dir, name)) == nil {
					n++
				}
			}
		}
	}
	// 清理旧版遗留在 run/ 下的 self_* 与 label_samples.* 膨胀文件(保留实时控制开关文件)
	runDir := filepath.Join(hncDir, "run")
	if entries, err := os.ReadDir(runDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if isProtectedRunSelfFile(name) {
				continue
			}
			if strings.HasPrefix(name, "self_") || strings.HasPrefix(name, "label_samples.") {
				if os.Remove(filepath.Join(runDir, name)) == nil {
					n++
				}
			}
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
	// v5.26 T3: rc17_process_health.sh 已删, 先把 Go 版 proc_health 快照写到
	// run/proc_health.json, debug_bundle.sh 拷进诊断包(Android 无 curl, 不走 loopback)。
	if b, err := json.Marshal(buildProcHealth(procfind.New(), hncDir, time.Now())); err == nil {
		_ = writeFileAtomic(filepath.Join(hncDir, "run", "proc_health.json"), b)
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

// ── DPI 规则库(纯 Go 在线更新: net/http + sha256 + archive/zip 防 ZipSlip) ──

const (
	dpiRulesDefaultRepo     = "lcx08091-source/hnc-v6"
	dpiRulesMaxReleaseBytes = 2 * 1024 * 1024 // 2 MB release metadata JSON
	dpiRulesMaxSHABytes     = 4096            // 4 KB .sha256 manifest
	dpiRulesMaxZipBytes     = 8 * 1024 * 1024 // 8 MB dpi-rules.zip
	dpiRulesMaxJSONBytes    = 512 * 1024      // 512 KB extracted rules json
)

// 单测注入点(生产保持默认零值, 严格强制 HTTPS 与重定向协议守卫)。
var (
	dpiRulesReleaseURL string
	dpiRulesHTTPClient *http.Client
	dpiRulesAllowHTTP  bool
)

func actionDPIRulesReset(hncDir string) actionResp {
	rc, out := runBin(hncDir, "dpi_rules_import.sh", "--reset")
	if rc != 0 {
		return actionResp{OK: false, Error: "reset failed", Detail: lastLine(out)}
	}
	return actionResp{OK: true, Detail: lastLine(out)}
}

// hasFakeDPIRulesUpdateStub 判断是否为特定脚本测试桩环境(如 simTestEnv 生成的探针脚本):
// 生产脚本含特定签名注释, 一律走纯 Go 主路径; 仅当存在自定义假脚本桩时回退调用脚本。
func hasFakeDPIRulesUpdateStub(hncDir string) bool {
	p := filepath.Join(hncDir, "bin", "dpi_rules_update.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	return !bytes.Contains(b, []byte("dpi_rules_update.sh — DPI"))
}

func actionDPIRulesUpdate(hncDir string, p map[string]string) actionResp {
	mode := p["mode"]
	flag := map[string]string{"check": "--check", "install": "--install"}[mode]
	if flag == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be check/install"}
	}
	if hasFakeDPIRulesUpdateStub(hncDir) {
		rc, out := runBin(hncDir, "dpi_rules_update.sh", flag)
		out = strings.TrimSpace(out)
		if rc != 0 {
			return actionResp{OK: false, Error: "update failed", Detail: lastLine(out)}
		}
		if flag == "--check" {
			if i := strings.LastIndex(out, "{"); i >= 0 && json.Valid([]byte(out[i:])) {
				out = out[i:]
			}
		}
		return actionResp{OK: true, Detail: out}
	}
	out, err := dpiRulesUpdateNative(hncDir, mode)
	if err != nil {
		dpiRulesUpdateLog(hncDir, "ERR: "+err.Error())
		return actionResp{OK: false, Error: "update failed", Detail: lastLine(err.Error())}
	}
	return actionResp{OK: true, Detail: out}
}

func dpiRulesUpdateLog(hncDir, msg string) {
	logDir := filepath.Join(hncDir, "logs")
	_ = os.MkdirAll(logDir, 0o755)
	f, err := os.OpenFile(filepath.Join(logDir, "dpi_rules_update.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "[%s] [RULES-UPD] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

func isAllowedDPIRulesHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "api.github.com" || host == "github.com" {
		return true
	}
	return strings.HasSuffix(host, ".githubusercontent.com") && len(host) > len(".githubusercontent.com")
}

func dpiRulesValidateURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u == nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid rules download URL: %s", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(dpiRulesAllowHTTP && scheme == "http") {
		return fmt.Errorf("refusing non-HTTPS URL: %s", rawURL)
	}
	if strings.TrimSpace(dpiRulesReleaseURL) == "" {
		host := u.Hostname()
		if !isAllowedDPIRulesHost(host) {
			return fmt.Errorf("disallowed rules download host: %s", host)
		}
	}
	return nil
}

func dpiRulesURLAllowed(u string) bool {
	return dpiRulesValidateURL(u) == nil
}

func dpiRulesVersionMatches(curVer, remoteVer string) bool {
	if remoteVer == "" {
		return false
	}
	return curVer == remoteVer || curVer == "rules-"+remoteVer
}

func dpiRulesClient() *http.Client {
	if dpiRulesHTTPClient != nil {
		return dpiRulesHTTPClient
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return errors.New("too many redirects")
			}
			if err := dpiRulesValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}
}

func dpiRulesFetchBytes(rawURL string, accept string, timeout time.Duration, maxBytes int64) ([]byte, error) {
	if err := dpiRulesValidateURL(rawURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hnc_httpd-rules-updater")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := dpiRulesClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes limit", maxBytes)
	}
	if len(b) == 0 {
		return nil, errors.New("empty response body")
	}
	return b, nil
}

type dpiReleaseMeta struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func dpiRulesCurrentVersion(hncDir string) string {
	b, err := os.ReadFile(filepath.Join(hncDir, "etc", "dpi_rules_online.version"))
	if err != nil {
		return "builtin"
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v
	}
	return "builtin"
}

func dpiRulesUpdateNative(hncDir, mode string) (string, error) {
	apiURL := strings.TrimSpace(dpiRulesReleaseURL)
	if apiURL == "" {
		repo := strings.TrimSpace(os.Getenv("HNC_RULES_REPO"))
		if repo == "" {
			repo = dpiRulesDefaultRepo
		}
		apiURL = "https://api.github.com/repos/" + repo + "/releases/latest"
	}

	curVer := dpiRulesCurrentVersion(hncDir)
	metaRaw, err := dpiRulesFetchBytes(apiURL, "application/vnd.github+json", 30*time.Second, dpiRulesMaxReleaseBytes)
	if err != nil {
		return "", fmt.Errorf("cannot fetch release metadata: %w", err)
	}
	var meta dpiReleaseMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return "", fmt.Errorf("invalid release metadata JSON: %w", err)
	}
	remoteVer := strings.TrimSpace(meta.TagName)
	if remoteVer == "" {
		return "", errors.New("no tag_name in release response")
	}
	for _, r := range remoteVer {
		if unicode.IsControl(r) || len(remoteVer) > 64 {
			return "", errors.New("invalid tag_name in release response")
		}
	}

	if mode == "check" {
		avail := "no"
		if !dpiRulesVersionMatches(curVer, remoteVer) {
			avail = "yes"
		}
		b, _ := json.Marshal(map[string]string{
			"current":          curVer,
			"remote":           remoteVer,
			"update_available": avail,
		})
		return string(b), nil
	}

	if dpiRulesVersionMatches(curVer, remoteVer) {
		return "ok: rules already at " + curVer, nil
	}

	var dlURL, shaURL string
	for _, a := range meta.Assets {
		u := strings.TrimSpace(a.BrowserDownloadURL)
		switch {
		case a.Name == "dpi-rules.zip" || (strings.HasSuffix(u, "dpi-rules.zip") && dlURL == ""):
			dlURL = u
		case a.Name == "dpi-rules.zip.sha256" || (strings.HasSuffix(u, "dpi-rules.zip.sha256") && shaURL == ""):
			shaURL = u
		}
	}
	if dlURL == "" {
		return "", fmt.Errorf("release %s has no dpi-rules.zip attachment", remoteVer)
	}
	if shaURL == "" {
		return "", fmt.Errorf("release %s has no dpi-rules.zip.sha256 attachment", remoteVer)
	}

	shaRaw, err := dpiRulesFetchBytes(shaURL, "", 30*time.Second, dpiRulesMaxSHABytes)
	if err != nil {
		return "", fmt.Errorf("download sha256 failed: %w", err)
	}
	fields := strings.Fields(string(shaRaw))
	if len(fields) == 0 || !isValid64Hex(fields[0]) {
		return "", errors.New("invalid sha256 digest in manifest")
	}
	expectSHA := strings.ToLower(fields[0])

	zipRaw, err := dpiRulesFetchBytes(dlURL, "", 90*time.Second, dpiRulesMaxZipBytes)
	if err != nil {
		return "", fmt.Errorf("download zip failed: %w", err)
	}
	sum := sha256.Sum256(zipRaw)
	actualSHA := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actualSHA), []byte(expectSHA)) != 1 {
		return "", fmt.Errorf("sha256 mismatch: expected %s got %s", expectSHA, actualSHA)
	}

	ruleBytes, err := extractValidatedDPIRulesZip(zipRaw)
	if err != nil {
		return "", err
	}
	newVer, err := validateOnlineDPIRulesJSON(ruleBytes, remoteVer)
	if err != nil {
		return "", err
	}

	dstDir := filepath.Join(hncDir, "etc", "dpi_rules.d")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir dpi_rules.d failed: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dstDir, "97-online-update.json"), ruleBytes); err != nil {
		return "", fmt.Errorf("install rules failed: %w", err)
	}
	_ = writeFileAtomic(filepath.Join(hncDir, "etc", "dpi_rules_online.version"), []byte(newVer))
	dpiRulesUpdateLog(hncDir, "installed rules version "+newVer)
	triggerDPIRulesRebind(hncDir)
	return fmt.Sprintf("ok: rules updated to %s (installed as 97-online-update)", newVer), nil
}

// isSafeZipEntryName 严格拦截 ZipSlip 路径穿越(绝对路径、反斜杠、空段或 "..")。
func isSafeZipEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return false
		}
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	return clean != ".." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/")
}

func extractValidatedDPIRulesZip(zipRaw []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipRaw), int64(len(zipRaw)))
	if err != nil {
		return nil, fmt.Errorf("invalid zip archive: %w", err)
	}
	if len(zr.File) > 64 {
		return nil, fmt.Errorf("zip archive has too many entries (%d > 64)", len(zr.File))
	}
	var target, fallback *zip.File
	for _, zf := range zr.File {
		if !isSafeZipEntryName(zf.Name) {
			return nil, fmt.Errorf("unsafe zip entry path rejected: %s", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if !zf.Mode().IsRegular() {
			return nil, fmt.Errorf("non-regular zip entry rejected: %s", zf.Name)
		}
		base := path.Base(zf.Name)
		isPreferred := strings.HasSuffix(base, ".json") && strings.TrimSuffix(base, ".json") == "dpi_rules"
		if isPreferred {
			if target == nil {
				target = zf
			}
		} else if strings.HasSuffix(base, ".json") && fallback == nil {
			fallback = zf
		}
	}
	if target == nil {
		target = fallback
	}
	if target == nil {
		return nil, errors.New("zip has no rules json")
	}
	if target.UncompressedSize64 > dpiRulesMaxJSONBytes {
		return nil, fmt.Errorf("rules json exceeds %d bytes limit", dpiRulesMaxJSONBytes)
	}
	rc, err := target.Open()
	if err != nil {
		return nil, fmt.Errorf("open zip entry failed: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, dpiRulesMaxJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read zip entry failed: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("extracted rules json is empty")
	}
	if len(data) > dpiRulesMaxJSONBytes {
		return nil, fmt.Errorf("extracted rules json exceeds %d bytes limit", dpiRulesMaxJSONBytes)
	}
	return data, nil
}

func validateOnlineDPIRulesJSON(raw []byte, fallbackVer string) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return "", errors.New("downloaded rules failed JSON validation")
	}
	var doc struct {
		RulesVersion string            `json:"rules_version"`
		Rules        []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(trimmed, &doc); err != nil || doc.Rules == nil {
		return "", errors.New("downloaded rules missing top-level rules array")
	}
	if strings.ContainsAny(doc.RulesVersion, "\r\n") {
		return "", errors.New("invalid rules_version in downloaded rules")
	}
	ver := strings.TrimSpace(doc.RulesVersion)
	if len(ver) > 64 {
		return "", errors.New("invalid rules_version in downloaded rules")
	}
	for _, r := range ver {
		if unicode.IsControl(r) {
			return "", errors.New("invalid rules_version in downloaded rules")
		}
	}
	if ver == "" {
		ver = fallbackVer
	}
	return ver, nil
}

func triggerDPIRulesRebind(hncDir string) {
	rebindScript := filepath.Join(hncDir, "bin", "dpi_rebind.sh")
	if st, err := os.Stat(rebindScript); err != nil || st.IsDir() {
		return
	}
	explicitIdle := false
	if sb, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		for _, ln := range strings.Split(string(sb), "\n") {
			upper := strings.ToUpper(strings.TrimSpace(ln))
			if upper == "" {
				continue
			}
			if strings.HasPrefix(upper, "ACTIVE:") {
				explicitIdle = false
			} else if isExplicitIdleStateLine(upper) {
				explicitIdle = true
			}
		}
	}
	iface := "auto"
	if !explicitIdle {
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hotspot_iface")); err == nil {
			if v := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]); v != "" && ifaceNameOK(v) {
				iface = v
			}
		}
	}
	_, _ = runBin(hncDir, "dpi_rebind.sh", iface)
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
		runDir := filepath.Join(s.hncDir, "run")
		_ = os.MkdirAll(runDir, 0o755)
		tf, err := os.CreateTemp(runDir, "dpi_rules_upload.json.tmp.*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "write failed"})
			return
		}
		tmp := tf.Name()
		defer os.Remove(tmp)
		_ = tf.Chmod(0o600)
		if _, werr := tf.Write(body); werr != nil {
			_ = tf.Close()
			_ = os.Remove(tmp)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "write failed"})
			return
		}
		if cerr := tf.Close(); cerr != nil {
			_ = os.Remove(tmp)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": "write failed"})
			return
		}
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

var (
	runStatusMarkRE = regexp.MustCompile(`0x(80|008|0*[89a-eA-E][0-9a-fA-F]0000)`)
	runStatusTCFn   = countKernelTCRules
	runStatusIptFn  = countMangleMarkRules
)

func readRunStatusIface(hncDir string) string {
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "ACTIVE:") {
				if v := strings.TrimSpace(strings.TrimPrefix(ln, "ACTIVE:")); v != "" && ifaceNameOK(v) {
					return v
				}
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "iface.cache")); err == nil {
		if v := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]); v != "" && ifaceNameOK(v) {
			return v
		}
	}
	return ""
}

// countKernelTCRules 纯 Go 经 RTNetlink 统计热点口与 ifb0 的 qdisc + class 总数(兼容测试环境无接口/无权限返回 0)。
func countKernelTCRules(iface string) int {
	if iface == "" {
		return 0
	}
	total := 0
	seen := map[string]bool{}
	for _, name := range []string{iface, "ifb0"} {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ifi, err := net.InterfaceByName(name)
		if err != nil || ifi == nil || ifi.Index <= 0 {
			continue
		}
		if qs, err := nlroute.QdiscList(ifi.Index); err == nil {
			total += len(qs)
		}
		if cs, err := nlDumpHTBClassStats(ifi.Index); err == nil {
			total += len(cs)
		}
	}
	return total
}

func findIptablesBin() string {
	for _, dir := range []string{"/system/bin", "/system/xbin", "/vendor/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		cand := filepath.Join(dir, "iptables")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	if p, err := exec.LookPath("iptables"); err == nil {
		return p
	}
	return ""
}

func countMangleMarkRules() int {
	iptBin := findIptablesBin()
	if iptBin == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := hardenCmd(exec.CommandContext(ctx, iptBin, "-w", "1", "-t", "mangle", "-S")).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, ln := range strings.Split(string(out), "\n") {
		if runStatusMarkRE.MatchString(ln) {
			n++
		}
	}
	return n
}

// apiRunStatus 纯 Go 读取 run/hnc_state、/proc/<pid>/status VmRSS(修复原生 Android 无 awk
// 导致 hotspotd_rss_kb 恒为 0)与内核 qdisc/class 计数。
func (s *server) apiRunStatus(w http.ResponseWriter, r *http.Request) {
	iface := readRunStatusIface(s.hncDir)
	pfs := watchdogProcFS()
	tab := pfs.Table()
	hpid := pfs.FindPID(procfind.Spec("hotspotd"), s.hncDir, tab)
	hotspotdState := "down"
	rssKB := 0
	if hpid > 0 {
		hotspotdState = "up"
		if st, err := pfs.ReadFile(fmt.Sprintf("/proc/%d/status", hpid)); err == nil {
			rssKB = int(scParseVmRSS(string(st)))
		}
	} else {
		hpid = 0
	}
	wd := readWatchdogState(s.hncDir, time.Now())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hotspotd":        hotspotdState,
		"hotspotd_pid":    hpid,
		"hotspotd_rss_kb": rssKB,
		"tc_rules":        runStatusTCFn(iface),
		"ipt_rules":       runStatusIptFn(),
		"watchdog":        wd.count(),
		"watchdog_kind":   wd.Kind,
		"watchdog_pid":    wd.PID,
		"watchdog_hb_age": wd.HeartbeatAge,
		"iface":           iface,
	})
}

// watchdogState v5.25: 看门狗是否在跑。
type watchdogState struct {
	PID          int    `json:"pid"`
	Kind         string `json:"kind"`          // go | ""(没在跑)
	HeartbeatAge int64  `json:"heartbeat_age"` // 秒; -1 = 没在跑 / 无心跳文件
}

func (w watchdogState) count() int {
	if w.Kind == "" {
		return 0
	}
	return 1
}

// watchdogProcFS 测试注入(默认真实 /proc)。
var watchdogProcFS = procfind.New

func readWatchdogState(hncDir string, now time.Time) watchdogState {
	st := watchdogState{HeartbeatAge: -1}
	pid := watchdogProcFS().FindPID(procfind.Spec("watchdog"), hncDir, nil)
	if pid <= 0 {
		return st
	}
	st.PID, st.Kind = pid, "go"
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "watchdog.heartbeat")); err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && ts > 0 {
			st.HeartbeatAge = now.Unix() - ts
		}
	}
	return st
}

// /api/proc_health 的 Go 实现见 proc_health.go(v5.26 T3 删除了
// bin/rc17_process_health.sh, 不再透传)。

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

func createSyncedTempFile(path string, b []byte, perm os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return "", err
	}
	if n, err := f.Write(b); err != nil || n != len(b) {
		_ = f.Close()
		if err != nil {
			return "", err
		}
		return "", io.ErrShortWrite
	}
	if err := f.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return tmp, nil
}

func writeFileAtomicWithPerm(path string, b []byte, perm os.FileMode) error {
	tmp, err := createSyncedTempFile(path, b, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeFileAtomic(path string, b []byte) error {
	return writeFileAtomicWithPerm(path, b, 0o644)
}
