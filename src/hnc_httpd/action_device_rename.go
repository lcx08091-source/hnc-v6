package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// device_names.json file lives under <HNC_DIR>/data/, format is a flat
// JSON map { "aa:bb:cc:dd:ee:ff": "Mi-10", ... } that hotspotd reads via
// hnc_lookup_manual_name() at every device-discovery cycle. The C reader
// already exists since v3.5.0; this action exposes a writer to the WebUI.

const deviceNamesRelPath = "data/device_names.json"

// Serialize writes to avoid lost updates when two browser tabs rename
// different devices simultaneously. The file is tiny (< 4KB typical) so
// load-modify-store is fine.
var deviceNamesWriteMu sync.Mutex

// actionDeviceRename: rename one device. p["mac"] required, p["name"] optional.
// Empty name removes the manual override (so device falls back to DHCP / OUI).
//
// Validation:
//   - mac must be canonical aa:bb:cc:dd:ee:ff (lowercased on save)
//   - name must be 1-32 chars, printable, no newlines
//
// Concurrency:
//   - mu-protected load-modify-store
//   - atomic write via tmp + rename
func actionDeviceRename(hncDir string, p map[string]string) actionResp {
	mac := normalizeMAC(p["mac"])
	if mac == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac format, expected aa:bb:cc:dd:ee:ff"}
	}
	name := strings.TrimSpace(p["name"])
	if !validDeviceName(name) {
		return actionResp{OK: false, Error: "bad params", Detail: "name must be 1-32 printable chars, or empty to clear"}
	}

	path := filepath.Join(hncDir, deviceNamesRelPath)

	deviceNamesWriteMu.Lock()
	defer deviceNamesWriteMu.Unlock()

	names, err := loadDeviceNames(path)
	if err != nil {
		return actionResp{OK: false, Error: "read failed", Detail: err.Error()}
	}

	if name == "" {
		if _, existed := names[mac]; !existed {
			return actionResp{OK: true, Detail: "no manual name set; nothing to clear"}
		}
		delete(names, mac)
	} else {
		names[mac] = name
	}

	if err := saveDeviceNames(path, names); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}

	if name == "" {
		return actionResp{OK: true, Detail: fmt.Sprintf("cleared name for %s", mac)}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("set %s -> %q", mac, name)}
}

// loadDeviceNames reads the existing JSON map. Returns an empty map when
// the file is missing (first-ever rename).
func loadDeviceNames(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		// File exists but is malformed. Don't silently overwrite — surface error.
		return nil, fmt.Errorf("device_names.json malformed: %v", err)
	}
	return m, nil
}

// saveDeviceNames writes atomically: tmp file + rename. Lower-cases keys
// so reader's case-insensitive lookup stays predictable.
func saveDeviceNames(path string, m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// Normalize keys to lower case.
	normalized := make(map[string]string, len(m))
	for k, v := range m {
		normalized[strings.ToLower(strings.TrimSpace(k))] = v
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// normalizeMAC validates and canonicalizes a MAC address to lowercase
// colon-separated 17-char form. Returns "" on any parse failure.
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// Accept aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
	if len(s) != 17 {
		return ""
	}
	out := []byte(s)
	for i, c := range out {
		switch i {
		case 2, 5, 8, 11, 14:
			if c != ':' && c != '-' {
				return ""
			}
			out[i] = ':'
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return ""
			}
		}
	}
	return string(out)
}

// validDeviceName: empty (clear) is OK; otherwise 1-32 printable, no control chars.
func validDeviceName(s string) bool {
	if s == "" {
		return true // empty = clear
	}
	if len(s) > 32 {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			return false
		}
		if r < 0x20 {
			return false
		}
		// Disallow ", \, control chars that could break JSON encoding.
		// json.Marshal handles escapes, but we filter for cleanliness.
	}
	return true
}
