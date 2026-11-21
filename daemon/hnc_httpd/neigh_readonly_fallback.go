package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hnc.io/dpid/neigh"
)

const (
	neighRefreshFallbackWindow = 15 * time.Second
	neighDevicesStaleAfter     = 45 * time.Second
	neighSampleCooldown        = 2 * time.Second
	neighStaleMaxConfirmedAgo  = 90 * time.Second
	neighFallbackRegPruneAt    = 16
)

var (
	neighTestHookInstalled atomic.Bool

	neighDumpIfFn = neigh.DumpIf

	neighIfaceIndexFn = func(ifaceName string) (int, error) {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return 0, err
		}
		return ifi.Index, nil
	}

	neighIfaceReadyFn = defaultNeighIfaceReady

	neighNowFn = time.Now

	neighFallbackRegMtx sync.Mutex
	neighFallbackReg    = make(map[string]*neighFallbackDirState)
)

type neighFallbackDirState struct {
	mtx           sync.Mutex
	armedUntil    time.Time
	cachedIface   string
	cachedIfIndex int
	cachedAt      time.Time
	cachedEntries []neigh.Entry
}

type neighBestCandidate struct {
	bestIP        string
	ipRank        int // 3: IPv4, 2: Global/ULA IPv6, 1: Link-Local IPv6
	bestIPSeenSec int64
	linkLocalOnly bool
	seenSec       int64
}

func defaultNeighIfaceReady(ifaceName string) bool {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" || ifaceName == "lo" {
		return false
	}
	if isCellIface(ifaceName) || isVPNIface(ifaceName) {
		return false
	}
	return ifaceIPv4(ifaceName) != ""
}

func canUseNeighReadonlyFallback(hncDir string) bool {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(hncDir, "run", "neigh_fallback.disabled")); err == nil {
		return false
	}
	return neighTestHookInstalled.Load() || useNativeDataplane(hncDir)
}

func getNeighFallbackDirState(hncDir string) *neighFallbackDirState {
	cleanDir := filepath.Clean(strings.TrimSpace(hncDir))
	neighFallbackRegMtx.Lock()
	defer neighFallbackRegMtx.Unlock()
	if len(neighFallbackReg) >= neighFallbackRegPruneAt {
		now := neighNowFn()
		for k, entry := range neighFallbackReg {
			if k == cleanDir {
				continue
			}
			entry.mtx.Lock()
			expired := entry.armedUntil.IsZero() || !now.Before(entry.armedUntil)
			entry.mtx.Unlock()
			if expired {
				delete(neighFallbackReg, k)
			}
		}
	}
	st, exists := neighFallbackReg[cleanDir]
	if !exists {
		st = &neighFallbackDirState{}
		neighFallbackReg[cleanDir] = st
	}
	return st
}

func observeRefreshAckForNeighFallback(hncDir string) bool {
	if !canUseNeighReadonlyFallback(hncDir) {
		return false
	}
	reqPath := filepath.Join(hncDir, "run", "devices.refresh")
	reqBytes, err := os.ReadFile(reqPath)
	if err != nil {
		return false
	}
	reqToken := strings.TrimSpace(string(reqBytes))
	if reqToken == "" {
		return false
	}

	ackPath := filepath.Join(hncDir, "run", "devices.refresh.ack")
	ackBytes, ackErr := os.ReadFile(ackPath)
	ackToken := ""
	if ackErr == nil {
		ackToken = strings.TrimSpace(string(ackBytes))
	}

	st := getNeighFallbackDirState(hncDir)
	now := neighNowFn()
	st.mtx.Lock()
	defer st.mtx.Unlock()
	if ackErr != nil || ackToken != reqToken {
		st.armedUntil = now.Add(neighRefreshFallbackWindow)
		return true
	}
	st.armedUntil = time.Time{}
	return false
}

func readActiveHotspotIfaceFromState(hncDir string) (string, bool) {
	if strings.TrimSpace(hncDir) == "" {
		return "", false
	}
	raw, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state"))
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(string(raw))
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = strings.TrimSpace(line[:nl])
	}
	if !strings.HasPrefix(line, "ACTIVE:") {
		return "", false
	}
	ifaceName := strings.TrimSpace(strings.TrimPrefix(line, "ACTIVE:"))
	if sep := strings.IndexAny(ifaceName, " \t:"); sep >= 0 {
		ifaceName = ifaceName[:sep]
	}
	if ifaceName == "" {
		return "", false
	}
	return ifaceName, true
}

func (s *server) mergeReadonlyNeighFallback(devicesPath string, devicesMap map[string]any, nowSec int64) map[string]any {
	if s == nil || s.simActive() {
		return devicesMap
	}
	return mergeNeighReadonlyFallback(s.hncDir, devicesPath, devicesMap, nowSec)
}

func mergeNeighReadonlyFallback(hncDir, devicesPath string, devicesMap map[string]any, nowSec int64) map[string]any {
	if strings.TrimSpace(hncDir) == "" && strings.TrimSpace(devicesPath) != "" {
		hncDir = filepath.Dir(filepath.Dir(devicesPath))
	}
	if !canUseNeighReadonlyFallback(hncDir) {
		return devicesMap
	}
	ifaceName, active := readActiveHotspotIfaceFromState(hncDir)
	if !active || neighIfaceReadyFn == nil || !neighIfaceReadyFn(ifaceName) {
		return devicesMap
	}
	if strings.TrimSpace(devicesPath) == "" {
		devicesPath = filepath.Join(hncDir, "data", "devices.json")
	}

	now := neighNowFn()
	if nowSec <= 0 {
		nowSec = now.Unix()
	}

	st := getNeighFallbackDirState(hncDir)
	entries := st.sampleIfTriggered(ifaceName, devicesPath, now)
	if len(entries) == 0 {
		return devicesMap
	}

	byMAC, macOrder := selectUsableNeighByMAC(entries, nowSec)
	if len(byMAC) == 0 {
		return devicesMap
	}

	cloned := cloneDevicesMapForFallback(devicesMap, len(byMAC))
	for _, mac := range macOrder {
		cand := byMAC[mac]
		if existingKey, existingMap, found := findExistingDeviceByMAC(cloned, mac); found {
			if cand.bestIP != "" && (!cand.linkLocalOnly || stringFieldValue(existingMap["ip"]) == "") {
				existingMap["ip"] = cand.bestIP
			}
			if stringFieldValue(existingMap["mac"]) == "" {
				existingMap["mac"] = mac
			}
			if _, hasFirst := existingMap["first_seen"]; !hasFirst {
				existingMap["first_seen"] = float64(cand.seenSec)
			}
			if existingLastSeen, hasLast := neighLastSeenSec(existingMap["last_seen"]); !hasLast || cand.seenSec > existingLastSeen {
				existingMap["last_seen"] = float64(cand.seenSec)
			}
			cloned[existingKey] = existingMap
			continue
		}
		cloned[mac] = map[string]any{
			"ip":         cand.bestIP,
			"mac":        mac,
			"first_seen": float64(cand.seenSec),
			"last_seen":  float64(cand.seenSec),
		}
	}
	return cloned
}

func (st *neighFallbackDirState) sampleIfTriggered(ifaceName, devicesPath string, now time.Time) []neigh.Entry {
	st.mtx.Lock()
	defer st.mtx.Unlock()

	windowActive := !st.armedUntil.IsZero() && now.Before(st.armedUntil)
	if !windowActive {
		info, statErr := os.Stat(devicesPath)
		if statErr == nil && now.Sub(info.ModTime()) <= neighDevicesStaleAfter {
			return nil
		}
	}

	if st.cachedIface == ifaceName && !st.cachedAt.IsZero() && now.Sub(st.cachedAt) < neighSampleCooldown {
		return st.cachedEntries
	}

	ifindex, idxErr := neighIfaceIndexFn(ifaceName)
	if idxErr != nil || ifindex <= 0 {
		st.cachedIface = ifaceName
		st.cachedIfIndex = 0
		st.cachedAt = now
		st.cachedEntries = nil
		return nil
	}

	dumped, dumpErr := neighDumpIfFn(ifindex)
	if dumpErr != nil {
		st.cachedIface = ifaceName
		st.cachedIfIndex = ifindex
		st.cachedAt = now
		st.cachedEntries = nil
		return nil
	}

	filtered := make([]neigh.Entry, 0, len(dumped))
	for _, entry := range dumped {
		if entry.Deleted || !entry.Usable() {
			continue
		}
		if entry.IfIndex != 0 && entry.IfIndex != ifindex {
			continue
		}
		if entry.State == neigh.NUDStale && entry.HasCacheInfo && entry.ConfirmedAgo >= neighStaleMaxConfirmedAgo {
			continue
		}
		filtered = append(filtered, entry)
	}

	st.cachedIface = ifaceName
	st.cachedIfIndex = ifindex
	st.cachedAt = now
	st.cachedEntries = filtered
	return filtered
}

func selectUsableNeighByMAC(entries []neigh.Entry, nowSec int64) (map[string]neighBestCandidate, []string) {
	byMAC := make(map[string]neighBestCandidate, len(entries))
	order := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Deleted || !entry.Usable() {
			continue
		}
		seenSec := nowSec
		if entry.State == neigh.NUDStale && entry.HasCacheInfo {
			if entry.ConfirmedAgo >= neighStaleMaxConfirmedAgo {
				continue
			}
			if entry.ConfirmedAgo > 0 {
				seenSec = nowSec - int64(entry.ConfirmedAgo/time.Second)
				if seenSec < 0 {
					seenSec = 0
				}
			}
		}

		mac := strings.ToLower(strings.TrimSpace(entry.MAC))
		if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		ipAddr := entry.IP
		if len(ipAddr) == 0 || ipAddr.IsUnspecified() || ipAddr.IsMulticast() {
			continue
		}

		rank := 1
		ipText := ipAddr.String()
		if ip4 := ipAddr.To4(); ip4 != nil {
			rank = 3
			ipText = ip4.String()
		} else if !ipAddr.IsLinkLocalUnicast() {
			rank = 2
		}

		prev, seen := byMAC[mac]
		if !seen {
			order = append(order, mac)
			byMAC[mac] = neighBestCandidate{
				bestIP:        ipText,
				ipRank:        rank,
				bestIPSeenSec: seenSec,
				linkLocalOnly: rank == 1,
				seenSec:       seenSec,
			}
			continue
		}
		if seenSec > prev.seenSec {
			prev.seenSec = seenSec
		}
		if rank > prev.ipRank || (rank == prev.ipRank && seenSec > prev.bestIPSeenSec) {
			prev.bestIP = ipText
			prev.ipRank = rank
			prev.bestIPSeenSec = seenSec
			prev.linkLocalOnly = rank == 1
		}
		byMAC[mac] = prev
	}
	return byMAC, order
}

func neighLastSeenSec(v any) (int64, bool) {
	if n, ok := toInt64(v); ok {
		return n, true
	}
	if jn, ok := v.(json.Number); ok {
		if i, err := jn.Int64(); err == nil {
			return i, true
		}
		if f, err := jn.Float64(); err == nil {
			return int64(f), true
		}
	}
	return 0, false
}

func cloneDevicesMapForFallback(src map[string]any, extraCap int) map[string]any {
	cloned := make(map[string]any, len(src)+extraCap)
	for k, v := range src {
		if inner, isMap := v.(map[string]any); isMap {
			cp := make(map[string]any, len(inner)+2)
			for ik, iv := range inner {
				cp[ik] = iv
			}
			cloned[k] = cp
		} else {
			cloned[k] = v
		}
	}
	return cloned
}

func findExistingDeviceByMAC(cloned map[string]any, mac string) (string, map[string]any, bool) {
	if raw, exists := cloned[mac]; exists {
		if dm, isMap := raw.(map[string]any); isMap {
			return mac, dm, true
		}
	}
	for k, raw := range cloned {
		dm, isMap := raw.(map[string]any)
		if !isMap {
			continue
		}
		if strings.EqualFold(k, mac) || strings.EqualFold(stringFieldValue(dm["mac"]), mac) {
			return k, dm, true
		}
	}
	return "", nil, false
}

func stringFieldValue(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func resetNeighFallbackStateForTest() {
	neighFallbackRegMtx.Lock()
	neighFallbackReg = make(map[string]*neighFallbackDirState)
	neighFallbackRegMtx.Unlock()
}
