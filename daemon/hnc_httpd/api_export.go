// api_export.go — v5.5 export packager.
//
//   POST /api/export                     build a zip from time range
//   GET  /api/exports                    list built zips
//   GET  /api/exports/<name>             download
//
// Replaces AHNC's export workflow. The export captures everything Claude
// needs to do offline rule analysis WITHOUT a raw pcap (HNC has already
// parsed everything in real-time; the parsed metadata is enough).
//
// Zip layout:
//
//   manifest.json                schema v3, includes device + HNC version
//   dpi_state.json               current snapshot at export time
//   self_attrib/                 self_attrib.YYYYMMDD.jsonl files in range
//   stats/                       stats.YYYYMMDD.jsonl files in range
//   ip_app_map.json              current IP → app reverse map
//   dpi_rules.d/                 point-in-time copy of rule files

package main

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	osExec "os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	exportSchemaVersion  = "3"
	exportGetpropTimeout = 2 * time.Second
	exportTmpMaxAge      = time.Hour
	exportMaxKeepFiles   = 10
	exportMaxKeepBytes   = int64(128 << 20)
)

var (
	exportBuildPropPaths = []string{
		"/system/build.prop",
		"/product/etc/build.prop",
		"/vendor/build.prop",
	}
	exportStaticPropsOnce sync.Once
	exportStaticProps     map[string]string
	exportGetpropExec     = defaultExportGetpropExec
	exportCreateZipFile   = func(path string) (io.WriteCloser, error) { return os.Create(path) }
)

func parseBuildPropFiles(paths []string) map[string]string {
	props := make(map[string]string, 64)
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq <= 0 {
				continue
			}
			k := strings.TrimSpace(line[:eq])
			v := strings.Trim(strings.TrimSpace(line[eq+1:]), "\"")
			if k == "" || v == "" {
				continue
			}
			if props[k] == "" {
				props[k] = v
			}
		}
		_ = f.Close()
	}
	// Android Treble 分区属性别名回退(直接键存在时优先直接键)
	for _, alias := range [][2]string{
		{"ro.product.model", "ro.product.product.model"},
		{"ro.product.model", "ro.product.vendor.model"},
		{"ro.product.model", "ro.product.system.model"},
		{"ro.product.brand", "ro.product.product.brand"},
		{"ro.product.brand", "ro.product.vendor.brand"},
		{"ro.product.brand", "ro.product.system.brand"},
		{"ro.build.version.release", "ro.product.build.version.release"},
		{"ro.build.version.release", "ro.system.build.version.release"},
		{"ro.build.id", "ro.product.build.id"},
		{"ro.build.id", "ro.system.build.id"},
	} {
		if props[alias[0]] == "" && props[alias[1]] != "" {
			props[alias[0]] = props[alias[1]]
		}
	}
	return props
}

func getStaticBuildProp(key string) string {
	exportStaticPropsOnce.Do(func() {
		exportStaticProps = parseBuildPropFiles(exportBuildPropPaths)
	})
	return exportStaticProps[key]
}

func resetExportStaticPropsForTest() {
	exportStaticPropsOnce = sync.Once{}
	exportStaticProps = nil
}

func defaultExportGetpropExec(key string) (string, error) {
	binPath := ""
	for _, cand := range []string{"/system/bin/getprop", "/system/xbin/getprop", "/vendor/bin/getprop"} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			binPath = cand
			break
		}
	}
	if binPath == "" {
		p, err := osExec.LookPath("getprop")
		if err != nil {
			return "", nil
		}
		binPath = p
	}
	return runIsolatedGetpropBin(exportGetpropTimeout, binPath, key)
}

func runIsolatedGetpropBin(timeout time.Duration, binPath string, args ...string) (string, error) {
	if timeout <= 0 {
		timeout = exportGetpropTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hardenCmd(osExec.CommandContext(ctx, binPath, args...))
	cmd.Env = hubSanitizedAndroidEnv()
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
	out, err := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("getprop timed out after %v: %w", timeout, context.DeadlineExceeded)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func isExportTmpFile(name string) bool {
	return strings.HasSuffix(name, ".tmp") || strings.Contains(name, ".tmp.")
}

// pruneExportsDir 按修改时间清理 exports/ 目录:
//  1. 删除超过 1 小时的残留 .tmp 临时文件;
//  2. 正式导出文件按修改时间从新到旧最多保留 10 个且累计总大小不超过 128MB。
func pruneExportsDir(exportsDir string, now time.Time, protectName string) {
	entries, err := os.ReadDir(exportsDir)
	if err != nil {
		return
	}
	type exportFileMeta struct {
		name    string
		size    int64
		modTime time.Time
	}
	files := make([]exportFileMeta, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		info, err := e.Info()
		if err != nil {
			continue
		}
		if isExportTmpFile(n) {
			if !now.Before(info.ModTime()) && now.Sub(info.ModTime()) > exportTmpMaxAge {
				_ = os.Remove(filepath.Join(exportsDir, n))
			}
			continue
		}
		files = append(files, exportFileMeta{
			name:    n,
			size:    info.Size(),
			modTime: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		if !files[i].modTime.Equal(files[j].modTime) {
			return files[i].modTime.After(files[j].modTime)
		}
		return files[i].name > files[j].name
	})

	keptCount := 0
	var keptBytes int64
	for _, f := range files {
		if protectName != "" && f.name == protectName && keptCount == 0 {
			keptCount++
			keptBytes += f.size
			continue
		}
		if keptCount < exportMaxKeepFiles && keptBytes+f.size <= exportMaxKeepBytes {
			keptCount++
			keptBytes += f.size
			continue
		}
		_ = os.Remove(filepath.Join(exportsDir, f.name))
	}
}

type exportRequest struct {
	From  int64    `json:"from"`
	To    int64    `json:"to"`
	Notes []string `json:"notes"`
}

type exportResponse struct {
	Status      string                 `json:"status"`
	Name        string                 `json:"name"`
	SizeBytes   int64                  `json:"size_bytes"`
	DownloadURL string                 `json:"download_url"`
	Manifest    map[string]interface{} `json:"manifest"`
}

type exportManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   int64                  `json:"generated_at"`
	GeneratedISO  string                 `json:"generated_at_iso"`
	HNCVersion    string                 `json:"hnc_version"`
	TimeRange     map[string]interface{} `json:"time_range"`
	Device        map[string]string      `json:"device"`
	Tracks        map[string]trackInfo   `json:"tracks"`
	Notes         []string               `json:"notes,omitempty"`
}

type trackInfo struct {
	Included   bool     `json:"included"`
	FileCount  int      `json:"file_count"`
	BytesTotal int64    `json:"bytes_total"`
	Files      []string `json:"files,omitempty"`
}

func (s *server) exportsDir() string {
	return filepath.Join(s.hncDir, "exports")
}

// exportMu v5.11: 导出串行化。包名精确到秒, 同一秒内两个并发导出会写同一个
// <name>.zip.tmp → 两个 zip.Writer 交错写同一文件 → 包损坏; 且每次导出都要
// 读几十 MB 的 JSONL, 并发只会放大 IO。忙时直接 409, 不排队。
var exportMu sync.Mutex

func (s *server) apiExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !exportMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "export already in progress"})
		return
	}
	defer exportMu.Unlock()
	var req exportRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	now := time.Now()
	if req.To == 0 {
		req.To = now.Unix()
	}
	if req.From == 0 {
		req.From = req.To - 3600 // default last 1h
	}
	if req.From > req.To {
		req.From, req.To = req.To, req.From
	}
	const maxRange = int64(24 * 3600)
	if req.To-req.From > maxRange {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":          "time range too large",
			"max_range_secs": maxRange,
			"requested_secs": req.To - req.From,
		})
		return
	}
	if err := os.MkdirAll(s.exportsDir(), 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// 生成新包前先清理超时残留 .tmp 与超配额旧包, 提前释放磁盘余量防 ENOSPC
	pruneExportsDir(s.exportsDir(), now, "")

	name := fmt.Sprintf("hnc-export-%s.zip", now.Format("20060102-150405"))
	full := filepath.Join(s.exportsDir(), name)
	tmp := full + ".tmp"

	manifest := exportManifest{
		SchemaVersion: exportSchemaVersion,
		GeneratedAt:   now.Unix(),
		GeneratedISO:  now.Format(time.RFC3339),
		HNCVersion:    s.detectHNCVersion(),
		TimeRange: map[string]interface{}{
			"from":     req.From,
			"to":       req.To,
			"from_iso": time.Unix(req.From, 0).Format(time.RFC3339),
			"to_iso":   time.Unix(req.To, 0).Format(time.RFC3339),
		},
		Device: s.gatherDeviceInfo(),
		Tracks: map[string]trackInfo{},
		Notes:  req.Notes,
	}

	zf, err := exportCreateZipFile(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	abortZip := func(err error) {
		_ = zf.Close()
		_ = os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	zw := zip.NewWriter(zf)

	// Track: dpi_state.json (current snapshot)
	tState, err := addSingleFileToZip(zw, filepath.Join(s.hncDir, "run", "dpi_state.json"), "dpi_state.json")
	if err != nil {
		abortZip(err)
		return
	}
	if tState.Included {
		manifest.Tracks["dpi_state"] = tState
	}

	// Track: self_attrib JSONL files in range
	tSelf, err := s.addDailyJSONLToZip(zw, "self_attrib.", "self_attrib/", req.From, req.To)
	if err != nil {
		abortZip(err)
		return
	}
	manifest.Tracks["self_attrib"] = tSelf

	// Track: stats JSONL files (data/dpi_history preferred, fallback run/)
	tStats, err := s.addDailyJSONLToZip(zw, "stats.", "stats/", req.From, req.To)
	if err != nil {
		abortZip(err)
		return
	}
	manifest.Tracks["stats"] = tStats

	// Track: ip_app_map.json
	tIPMap, err := addSingleFileToZip(zw, filepath.Join(s.hncDir, "run", "ip_app_map.json"), "ip_app_map.json")
	if err != nil {
		abortZip(err)
		return
	}
	if tIPMap.Included {
		manifest.Tracks["ip_app_map"] = tIPMap
	}

	// Track: dpi_rules.d/ point-in-time snapshot
	tRules, err := s.addDPIRulesToZip(zw)
	if err != nil {
		abortZip(err)
		return
	}
	manifest.Tracks["dpi_rules"] = tRules

	// manifest.json LAST
	mw, err := zw.Create("manifest.json")
	if err != nil {
		abortZip(err)
		return
	}
	enc := json.NewEncoder(mw)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		abortZip(err)
		return
	}

	if err := zw.Close(); err != nil {
		abortZip(err)
		return
	}
	if err := zf.Close(); err != nil {
		_ = os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := os.Rename(tmp, full); err != nil {
		_ = os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// 新包落定后再次执行 10 个文件 / 128MB 硬上限配额修剪
	pruneExportsDir(s.exportsDir(), time.Now(), name)

	info, _ := os.Stat(full)
	var size int64
	if info != nil {
		size = info.Size()
	}
	mb, _ := json.Marshal(manifest)
	var mGeneric map[string]interface{}
	_ = json.Unmarshal(mb, &mGeneric)

	writeJSON(w, http.StatusOK, exportResponse{
		Status:      "ok",
		Name:        name,
		SizeBytes:   size,
		DownloadURL: "/api/exports/" + name,
		Manifest:    mGeneric,
	})
}

// addSingleFileToZip copies one file into the zip at the given archive path.
// Missing optional source files return Included=false, err=nil; ZIP/IO write errors (e.g. ENOSPC) are strictly propagated.
func addSingleFileToZip(zw *zip.Writer, src, archivePath string) (trackInfo, error) {
	info, err := os.Stat(src)
	if err != nil {
		if os.IsNotExist(err) {
			return trackInfo{Included: false}, nil
		}
		return trackInfo{Included: false}, err
	}
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return trackInfo{Included: false}, nil
		}
		return trackInfo{Included: false}, err
	}
	defer in.Close()
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return trackInfo{Included: false}, err
	}
	hdr.Name = archivePath
	hdr.Method = zip.Deflate
	out, err := zw.CreateHeader(hdr)
	if err != nil {
		return trackInfo{Included: false}, err
	}
	if _, err := io.Copy(out, in); err != nil {
		return trackInfo{Included: false}, err
	}
	return trackInfo{
		Included:   true,
		FileCount:  1,
		BytesTotal: info.Size(),
		Files:      []string{archivePath},
	}, nil
}

// addDailyJSONLToZip copies all *YYYYMMDD.jsonl files matching prefix whose day overlaps [from, to].
// Priority: data/dpi_history/ -> data/ -> run/ (deduplicated by filename, preferring newer persistent directory).
func (s *server) addDailyJSONLToZip(zw *zip.Writer, prefix, archiveDir string, from, to int64) (trackInfo, error) {
	keys := dayFileKeys(time.Unix(from, 0), time.Unix(to, 0))
	fromDay, toDay := keys[0], keys[len(keys)-1]

	scanDirs := []string{
		selfStudioDir(s.hncDir),
		filepath.Join(s.hncDir, "data", "dpi_history"),
		filepath.Join(s.hncDir, "data"),
		filepath.Join(s.hncDir, "run"),
	}
	chosenPath := make(map[string]string)
	for _, dir := range scanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".jsonl") {
				continue
			}
			day := strings.TrimSuffix(strings.TrimPrefix(n, prefix), ".jsonl")
			if day < fromDay || day > toDay {
				continue
			}
			if _, seen := chosenPath[n]; !seen {
				chosenPath[n] = filepath.Join(dir, n)
			}
		}
	}
	names := make([]string, 0, len(chosenPath))
	for n := range chosenPath {
		names = append(names, n)
	}
	sort.Strings(names)

	t := trackInfo{}
	for _, n := range names {
		sub, err := addSingleFileToZip(zw, chosenPath[n], archiveDir+n)
		if err != nil {
			return trackInfo{Included: false}, err
		}
		if !sub.Included {
			continue
		}
		t.Files = append(t.Files, n)
		t.BytesTotal += sub.BytesTotal
		t.FileCount++
	}
	t.Included = t.FileCount > 0
	return t, nil
}

// addDPIRulesToZip copies data/dpi_rules.d/*.json into the zip.
func (s *server) addDPIRulesToZip(zw *zip.Writer) (trackInfo, error) {
	files := dpiRuleFiles(s.hncDir)
	if len(files) == 0 {
		return trackInfo{Included: false}, nil
	}
	t := trackInfo{}
	for _, fullPath := range files {
		n := filepath.Base(fullPath)
		sub, err := addSingleFileToZip(zw, fullPath, "dpi_rules.d/"+n)
		if err != nil {
			return trackInfo{Included: false}, err
		}
		if !sub.Included {
			continue
		}
		t.Files = append(t.Files, n)
		t.BytesTotal += sub.BytesTotal
		t.FileCount++
	}
	t.Included = t.FileCount > 0
	sort.Strings(t.Files)
	return t, nil
}

// gatherDeviceInfo reads static ro.* properties from build.prop first (sync.Once),
// falling back to 2s-isolated getprop only for missing keys so exportMu can never deadlock.
func (s *server) gatherDeviceInfo() map[string]string {
	d := map[string]string{
		"arch": runtime.GOARCH,
	}
	getpropTimedOut := false
	for _, p := range []struct {
		key, prop string
	}{
		{"model", "ro.product.model"},
		{"brand", "ro.product.brand"},
		{"android_version", "ro.build.version.release"},
		{"build_id", "ro.build.id"},
	} {
		v := getStaticBuildProp(p.prop)
		if v == "" && !getpropTimedOut {
			var err error
			v, err = getpropCmd(p.prop)
			if errors.Is(err, context.DeadlineExceeded) {
				getpropTimedOut = true
			}
		}
		if v != "" {
			d[p.key] = v
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		d["kernel"] = strings.TrimSpace(string(b))
	}
	return d
}

// detectHNCVersion 统一经 ServerVersion 获取控制面版本(编译期注入优先, 回退 module.prop)。
func (s *server) detectHNCVersion() string {
	if v := s.serverVersion(); v != "" && v != "dev" {
		return v
	}
	for _, p := range []string{
		filepath.Join(s.hncDir, "module.prop"),
		filepath.Join(moduleDir(s.hncDir), "module.prop"),
		"/data/adb/modules/hotspot_net_ctl/module.prop",
		"/data/adb/modules/hotspot_network_control/module.prop",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if v := propLine(string(b), "version"); v != "" {
			return v
		}
	}
	return s.serverVersion()
}

func (s *server) runGetprop(key string) string {
	if v := getStaticBuildProp(key); v != "" {
		return v
	}
	out, err := getpropCmd(key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// ─── list + download ──────────────────────────────────────────────────

func (s *server) apiExportList(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.exportsDir())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"exports": []interface{}{}})
		return
	}
	type item struct {
		Name        string `json:"name"`
		Size        int64  `json:"size"`
		Modified    string `json:"modified"`
		DownloadURL string `json:"download_url"`
	}
	out := make([]item, 0, len(entries))
	for _, e := range entries {
		n := e.Name()
		if !isExportArchive(n) { // v5.11: 诊断包 hnc-debug-*.tar.gz 也在这里
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, item{
			Name:        n,
			Size:        info.Size(),
			Modified:    info.ModTime().Format(time.RFC3339),
			DownloadURL: "/api/exports/" + n,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	writeJSON(w, http.StatusOK, map[string]interface{}{"exports": out})
}

func (s *server) apiExportFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/exports/")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	if !isExportArchive(name) {
		http.Error(w, "must end in .zip or .tar.gz (or be a hnc-selfcheck-*.txt/.json report)", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.exportsDir(), name)
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	ctype := "application/zip"
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		ctype = "application/gzip"
	case strings.HasSuffix(name, ".txt"): // v5.20 自检报告
		ctype = "text/plain; charset=utf-8"
	case strings.HasSuffix(name, ".json"):
		ctype = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, path)
}

func getpropCmd(key string) (string, error) {
	if exportGetpropExec == nil {
		return "", nil
	}
	out, err := exportGetpropExec(key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// isExportArchive v5.11: /api/exports 可列出/下载的产物 —— 数据导出 .zip 与诊断包 .tar.gz。
// v5.20: + 自检报告 hnc-selfcheck-*.txt / .json(见 selfcheck_api.go)。
func isExportArchive(n string) bool {
	return strings.HasSuffix(n, ".zip") || strings.HasSuffix(n, ".tar.gz") || isSelfcheckExport(n) || isRulepackExport(n) || isCompatExport(n) || isCaptureRecPcap(n) // v5.29 T5/T4
}
