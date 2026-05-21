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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	osExec "os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// osExecCommand is an alias of os/exec.Command to allow renaming in
// tests without exposing the import everywhere.
var osExecCommand = osExec.Command

const exportSchemaVersion = "3"

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

func (s *server) apiExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
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
			"error":           "time range too large",
			"max_range_secs":  maxRange,
			"requested_secs":  req.To - req.From,
		})
		return
	}
	if err := os.MkdirAll(s.exportsDir(), 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
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

	zf, err := os.Create(tmp)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	zw := zip.NewWriter(zf)

	// Track: dpi_state.json (current snapshot)
	if t, err := addSingleFileToZip(zw,
		filepath.Join(s.hncDir, "run", "dpi_state.json"),
		"dpi_state.json"); err == nil {
		manifest.Tracks["dpi_state"] = t
	}

	// Track: self_attrib JSONL files in range
	manifest.Tracks["self_attrib"] = s.addDailyJSONLToZip(zw, "self_attrib.",
		"self_attrib/", req.From, req.To)

	// Track: stats JSONL files (existing HNC history)
	manifest.Tracks["stats"] = s.addDailyJSONLToZip(zw, "stats.",
		"stats/", req.From, req.To)

	// Track: ip_app_map.json
	if t, err := addSingleFileToZip(zw,
		filepath.Join(s.hncDir, "run", "ip_app_map.json"),
		"ip_app_map.json"); err == nil {
		manifest.Tracks["ip_app_map"] = t
	}

	// Track: dpi_rules.d/ point-in-time snapshot
	manifest.Tracks["dpi_rules"] = s.addDPIRulesToZip(zw)

	// manifest.json LAST
	if mw, err := zw.Create("manifest.json"); err == nil {
		enc := json.NewEncoder(mw)
		enc.SetIndent("", "  ")
		_ = enc.Encode(manifest)
	}

	if err := zw.Close(); err != nil {
		zf.Close()
		os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := zf.Close(); err != nil {
		os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := os.Rename(tmp, full); err != nil {
		os.Remove(tmp)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	info, _ := os.Stat(full)
	var size int64
	if info != nil {
		size = info.Size()
	}
	// JSON-marshal+unmarshal to convert manifest struct to generic map
	// (mirrors AHNC's response shape so WebUI can iterate tracks).
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
// Returns a trackInfo with included=true on success.
func addSingleFileToZip(zw *zip.Writer, src, archivePath string) (trackInfo, error) {
	info, err := os.Stat(src)
	if err != nil {
		return trackInfo{Included: false}, err
	}
	in, err := os.Open(src)
	if err != nil {
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

// addDailyJSONLToZip copies all *YYYYMMDD.jsonl files matching prefix
// in cfg.run dir whose day overlaps [from, to].
func (s *server) addDailyJSONLToZip(zw *zip.Writer, prefix, archiveDir string, from, to int64) trackInfo {
	runDir := filepath.Join(s.hncDir, "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return trackInfo{Included: false}
	}
	loc := time.Local
	fromDay := time.Unix(from, 0).In(loc).Format("20060102")
	toDay := time.Unix(to, 0).In(loc).Format("20060102")

	t := trackInfo{}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(n, prefix), ".jsonl")
		if day < fromDay || day > toDay {
			continue
		}
		sub, err := addSingleFileToZip(zw, filepath.Join(runDir, n), archiveDir+n)
		if err != nil {
			continue
		}
		t.Files = append(t.Files, n)
		t.BytesTotal += sub.BytesTotal
		t.FileCount++
	}
	t.Included = t.FileCount > 0
	sort.Strings(t.Files)
	return t
}

// addDPIRulesToZip copies data/dpi_rules.d/*.json into the zip.
func (s *server) addDPIRulesToZip(zw *zip.Writer) trackInfo {
	rulesDir := filepath.Join(s.hncDir, "data", "dpi_rules.d")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return trackInfo{Included: false}
	}
	t := trackInfo{}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		sub, err := addSingleFileToZip(zw, filepath.Join(rulesDir, n), "dpi_rules.d/"+n)
		if err != nil {
			continue
		}
		t.Files = append(t.Files, n)
		t.BytesTotal += sub.BytesTotal
		t.FileCount++
	}
	t.Included = t.FileCount > 0
	sort.Strings(t.Files)
	return t
}

// gatherDeviceInfo reads a few /system properties for the manifest.
func (s *server) gatherDeviceInfo() map[string]string {
	d := map[string]string{
		"arch": runtime.GOARCH,
	}
	for _, p := range []struct {
		key, prop string
	}{
		{"model", "ro.product.model"},
		{"brand", "ro.product.brand"},
		{"android_version", "ro.build.version.release"},
		{"build_id", "ro.build.id"},
	} {
		v := s.runGetprop(p.prop)
		if v != "" {
			d[p.key] = v
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		d["kernel"] = strings.TrimSpace(string(b))
	}
	return d
}

// detectHNCVersion reads HNC's own module.prop. Best-effort.
func (s *server) detectHNCVersion() string {
	for _, p := range []string{
		"/data/adb/modules/hotspot_network_control/module.prop",
		filepath.Join(s.hncDir, "module.prop"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "version=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "version="))
			}
		}
	}
	return ""
}

func (s *server) runGetprop(key string) string {
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
		if !strings.HasSuffix(n, ".zip") {
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
	if !strings.HasSuffix(name, ".zip") {
		http.Error(w, "must end in .zip", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.exportsDir(), name)
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, path)
}

// getpropCmd shells out to `getprop <key>`. Empty + nil-error on
// non-Android hosts (e.g. dev box) so this file compiles+links cleanly
// outside of an Android NDK build.
func getpropCmd(key string) (string, error) {
	out, err := execCommand("getprop", key)
	return out, err
}

// execCommand is a thin wrapper for swap-in-test-able exec.
func execCommand(name string, args ...string) (string, error) {
	cmd := osExecCommand(name, args...)
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
