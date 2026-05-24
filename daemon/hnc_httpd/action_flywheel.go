// action_flywheel.go — v5.7.0-rc35 · WebUI management of the flywheel
// VPN/proxy exclusion list.
//
//	flywheel_exclude_set  params: op=add|remove, pkg=<android.package.name>
//	    → load-modify-store etc/flywheel_exclude.json ("exclude_pkgs" list).
//	      dpid re-reads this file on its pkg-cache TTL (~5 min) and merges it
//	      with the built-in seed; listed packages never feed the flywheel.
//
// This only edits the USER list. The built-in seed (common VPN/proxy apps)
// and the conduit auto-detection are always on and not user-editable here.
// Serialized + atomic (tmp+rename), matching action_candidate.go.

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const flywheelExcludeRelPath = "etc/flywheel_exclude.json"

// android package name: dot-separated segments, each starting with a letter.
var pkgNameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)

func validPkgName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 || len(s) > 255 || !pkgNameRE.MatchString(s) {
		return "", false
	}
	return s, true
}

var flywheelExcludeMu sync.Mutex

// flywheelExcludeFile mirrors dpid's on-disk shape (output/flywheel_exclude.go).
type flywheelExcludeFile struct {
	ExcludePkgs []string `json:"exclude_pkgs"`
	Comment     string   `json:"_comment,omitempty"`
}

// actionFlywheelExcludeSet adds/removes a package from the user exclusion list.
func actionFlywheelExcludeSet(hncDir string, p map[string]string) actionResp {
	op := strings.TrimSpace(strings.ToLower(p["op"]))
	if op != "add" && op != "remove" {
		return actionResp{OK: false, Error: "bad params", Detail: "op must be add or remove"}
	}
	pkg, ok := validPkgName(p["pkg"])
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid package name (expected like com.example.app)"}
	}
	path := filepath.Join(hncDir, flywheelExcludeRelPath)

	flywheelExcludeMu.Lock()
	defer flywheelExcludeMu.Unlock()

	var f flywheelExcludeFile
	if err := readJSONInto(path, &f); err != nil {
		return actionResp{OK: false, Error: "read failed", Detail: err.Error()}
	}

	if op == "add" {
		if contains(f.ExcludePkgs, pkg) {
			return actionResp{OK: true, Detail: fmt.Sprintf("%s already excluded", pkg)}
		}
		f.ExcludePkgs = append(f.ExcludePkgs, pkg)
	} else { // remove
		out := f.ExcludePkgs[:0]
		removed := false
		for _, x := range f.ExcludePkgs {
			if x == pkg {
				removed = true
				continue
			}
			out = append(out, x)
		}
		f.ExcludePkgs = out
		if !removed {
			return actionResp{OK: true, Detail: fmt.Sprintf("%s was not in the user list", pkg)}
		}
	}
	f.Comment = "用户从 WebUI 维护的飞轮排除名单(VPN/代理);dpid 合并内置清单后每 ~5min 热加载。"
	if err := writeJSONAtomic(path, &f); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	verb := "excluded"
	if op == "remove" {
		verb = "un-excluded"
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("%s %s — dpid applies within ~5 min", verb, pkg)}
}

// loadFlywheelExcludeUser returns the user-added exclusion packages (never the
// built-in seed). Missing/malformed file = empty. Used by /api/config so the
// WebUI can show + manage the editable list.
func loadFlywheelExcludeUser(hncDir string) []string {
	var f flywheelExcludeFile
	if err := readJSONInto(filepath.Join(hncDir, flywheelExcludeRelPath), &f); err != nil {
		return nil
	}
	return f.ExcludePkgs
}
