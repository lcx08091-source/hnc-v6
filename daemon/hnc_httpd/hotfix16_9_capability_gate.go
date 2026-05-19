package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// hotfix16.9: generic capability reader. Unknown keeps legacy behavior; an
// explicit false from run/capabilities.json is authoritative and lets write
// actions fail fast instead of blocking in shell/tc paths.
func readCapabilityBool(hncDir, key string) (bool, bool) {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "capabilities.json"))
	if err != nil {
		return true, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return true, false
	}
	if v, ok := m[key].(bool); ok {
		return v, true
	}
	return true, false
}

func tcHTBSupported(hncDir string) (bool, bool) {
	return readCapabilityBool(hncDir, "tc_htb")
}

func tcNetemSupported(hncDir string) (bool, bool) {
	return readCapabilityBool(hncDir, "tc_netem")
}
