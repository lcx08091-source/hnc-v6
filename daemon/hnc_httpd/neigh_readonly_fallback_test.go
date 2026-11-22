package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

func installNeighTestHooks(
	t *testing.T,
	nowPtr *time.Time,
	nowMtx *sync.Mutex,
	ifaceIdx int,
	dumpFn func(int) ([]neigh.Entry, error),
) {
	t.Helper()
	origDump := neighDumpIfFn
	origIdx := neighIfaceIndexFn
	origNow := neighNowFn
	origReady := neighIfaceReadyFn
	origHook := neighTestHookInstalled.Load()

	resetNeighFallbackStateForTest()

	neighNowFn = func() time.Time {
		nowMtx.Lock()
		defer nowMtx.Unlock()
		return *nowPtr
	}
	neighIfaceIndexFn = func(name string) (int, error) {
		return ifaceIdx, nil
	}
	neighIfaceReadyFn = func(name string) bool {
		return true
	}
	neighDumpIfFn = dumpFn
	neighTestHookInstalled.Store(true)

	t.Cleanup(func() {
		neighDumpIfFn = origDump
		neighIfaceIndexFn = origIdx
		neighNowFn = origNow
		neighIfaceReadyFn = origReady
		neighTestHookInstalled.Store(origHook)
		resetNeighFallbackStateForTest()
	})
}

func TestNeighFallback_ActionRefreshTimeoutArms15sWindow(t *testing.T) {
	hncDir := t.TempDir()
	for _, sub := range []string{"bin", "run", "data"} {
		if err := os.MkdirAll(filepath.Join(hncDir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	var nowMtx sync.Mutex
	curNow := time.Unix(1795246800, 0)
	var dumpCalls atomic.Int32

	installNeighTestHooks(t, &curNow, &nowMtx, 7, func(ifindex int) ([]neigh.Entry, error) {
		dumpCalls.Add(1)
		return []neigh.Entry{
			{IfIndex: 7, IP: net.ParseIP("192.168.43.18"), MAC: "aa:bb:cc:11:22:33", State: neigh.NUDReachable},
			{IfIndex: 7, IP: net.ParseIP("fe80::a8bb:ccff:fe11:2233"), MAC: "aa:bb:cc:11:22:33", State: neigh.NUDStale},
			{IfIndex: 7, IP: net.ParseIP("192.168.43.29"), MAC: "aa:bb:cc:44:55:66", State: neigh.NUDStale},
			{IfIndex: 7, IP: net.ParseIP("192.168.43.91"), MAC: "aa:bb:cc:00:00:01", State: neigh.NUDIncomplete},
			{IfIndex: 7, IP: net.ParseIP("192.168.43.92"), MAC: "aa:bb:cc:00:00:02", State: neigh.NUDFailed},
			{IfIndex: 7, IP: net.ParseIP("192.168.43.93"), MAC: "00:00:00:00:00:00", State: neigh.NUDReachable},
			{IfIndex: 7, IP: net.ParseIP("192.168.43.94"), MAC: "aa:bb:cc:00:00:04", State: neigh.NUDReachable, Deleted: true},
			{IfIndex: 99, IP: net.ParseIP("10.0.0.1"), MAC: "aa:bb:cc:00:00:99", State: neigh.NUDReachable},
		}, nil
	})

	_ = os.WriteFile(filepath.Join(hncDir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644)
	devicesPath := filepath.Join(hncDir, "data", "devices.json")
	_ = os.WriteFile(devicesPath, []byte(`{"aa:bb:cc:11:22:33":{"ip":"192.168.43.10"}}`), 0o644)
	_ = os.Chtimes(devicesPath, curNow, curNow)

	mockDetect := filepath.Join(hncDir, "bin", "device_detect.sh")
	scriptBody := "#!/bin/sh\nprintf '9001-1795246800\\n' > \"" + filepath.Join(hncDir, "run", "devices.refresh") + "\"\nprintf '1\\n'\nexit 0\n"
	_ = os.WriteFile(mockDetect, []byte(scriptBody), 0o755)

	resp := actionRefresh(hncDir)
	if !resp.OK {
		t.Fatalf("actionRefresh failed: %+v", resp)
	}

	srv := &server{hncDir: hncDir}
	nowSec := curNow.Unix()
	sharedMap := map[string]any{
		"aa:bb:cc:11:22:33": map[string]any{
			"ip":         "192.168.43.10",
			"mac":        "aa:bb:cc:11:22:33",
			"first_seen": float64(nowSec - 600),
			"last_seen":  float64(nowSec - 200),
			"hostname":   "Work-Laptop",
		},
	}

	merged := srv.mergeReadonlyNeighFallback(devicesPath, sharedMap, nowSec)
	if len(merged) != 2 {
		t.Fatalf("merged len=%d, want 2: %#v", len(merged), merged)
	}
	dev1 := merged["aa:bb:cc:11:22:33"].(map[string]any)
	if dev1["ip"] != "192.168.43.18" || dev1["last_seen"] != float64(nowSec) || dev1["hostname"] != "Work-Laptop" {
		t.Fatalf("existing device merge mismatch: %#v", dev1)
	}
}

func TestNeighFallback_ZeroDiskWriteAndZeroJSONCacheMutation(t *testing.T) {
	hncDir := t.TempDir()
	for _, sub := range []string{"run", "data"} {
		_ = os.MkdirAll(filepath.Join(hncDir, sub), 0o755)
	}

	var nowMtx sync.Mutex
	curNow := time.Unix(1795248000, 0)
	var dumpCalls atomic.Int32
	installNeighTestHooks(t, &curNow, &nowMtx, 5, func(ifindex int) ([]neigh.Entry, error) {
		dumpCalls.Add(1)
		return []neigh.Entry{
			{IfIndex: 5, IP: net.ParseIP("192.168.43.88"), MAC: "12:34:56:78:9a:bc", State: neigh.NUDReachable},
			{IfIndex: 5, IP: net.ParseIP("192.168.43.89"), MAC: "12:34:56:78:9a:bd", State: neigh.NUDReachable},
		}, nil
	})

	_ = os.WriteFile(filepath.Join(hncDir, "run", "hnc_state"), []byte("ACTIVE:ap_br_wlan2\n"), 0o644)
	devicesPath := filepath.Join(hncDir, "data", "devices.json")
	origDiskContent := []byte("{\"12:34:56:78:9a:bc\":{\"ip\":\"192.168.43.2\",\"last_seen\":1795247000}}\n")
	_ = os.WriteFile(devicesPath, origDiskContent, 0o644)
	staleTime := curNow.Add(-90 * time.Second)
	_ = os.Chtimes(devicesPath, staleTime, staleTime)

	sharedInner := map[string]any{
		"ip":         "192.168.43.2",
		"mac":        "12:34:56:78:9a:bc",
		"first_seen": float64(1795246000),
		"last_seen":  float64(1795247000),
	}
	sharedCacheMap := map[string]any{
		"12:34:56:78:9a:bc": sharedInner,
	}

	srv := &server{hncDir: hncDir}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			m := srv.mergeReadonlyNeighFallback(devicesPath, sharedCacheMap, curNow.Unix())
			m["12:34:56:78:9a:bc"].(map[string]any)["worker"] = id
		}(i)
	}
	wg.Wait()

	if dumpCalls.Load() != 1 {
		t.Fatalf("2s cooldown failed: dumpCalls=%d want 1", dumpCalls.Load())
	}
	if len(sharedCacheMap) != 1 || sharedInner["ip"] != "192.168.43.2" {
		t.Fatalf("sharedCacheMap mutated: %#v", sharedCacheMap)
	}
	if _, leaked := sharedInner["worker"]; leaked {
		t.Fatalf("nested map mutation leaked into sharedCacheMap")
	}
	afterDisk, _ := os.ReadFile(devicesPath)
	if !bytes.Equal(origDiskContent, afterDisk) {
		t.Fatalf("disk devices.json modified!")
	}
}

func TestNeighFallback_UnhookedTempDirNeverCallsDumpIf(t *testing.T) {
	t.Run("unhooked_tempdir_with_active_lo_and_missing_devices", func(t *testing.T) {
		origDump := neighDumpIfFn
		origHook := neighTestHookInstalled.Load()
		neighTestHookInstalled.Store(false)
		resetNeighFallbackStateForTest()
		var dumpCalls atomic.Int32
		neighDumpIfFn = func(ifindex int) ([]neigh.Entry, error) {
			dumpCalls.Add(1)
			return []neigh.Entry{
				{IfIndex: ifindex, IP: net.ParseIP("127.0.0.1"), MAC: "aa:bb:cc:dd:ee:ff", State: neigh.NUDReachable},
			}, nil
		}
		t.Cleanup(func() {
			neighDumpIfFn = origDump
			neighTestHookInstalled.Store(origHook)
			resetNeighFallbackStateForTest()
		})

		hncDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(hncDir, "run"), 0o755)
		_ = os.MkdirAll(filepath.Join(hncDir, "data"), 0o755)
		_ = os.WriteFile(filepath.Join(hncDir, "run", "hnc_state"), []byte("ACTIVE:lo\n"), 0o644)
		_ = os.WriteFile(filepath.Join(hncDir, "run", "devices.refresh"), []byte("1234-1795249000\n"), 0o644)

		if observeRefreshAckForNeighFallback(hncDir) {
			t.Fatalf("observeRefreshAckForNeighFallback must return false in unhooked TempDir")
		}

		srv := &server{hncDir: hncDir}
		devicesPath := filepath.Join(hncDir, "data", "devices.json")
		origMap := map[string]any{}
		got := srv.mergeReadonlyNeighFallback(devicesPath, origMap, 1795249000)
		if len(got) != 0 {
			t.Fatalf("unexpected fallback devices in unhooked TempDir: %#v", got)
		}
		if dumpCalls.Load() != 0 {
			t.Fatalf("DumpIf called %d times in unhooked TempDir, want 0", dumpCalls.Load())
		}

		for _, badIface := range []string{"", "lo", "rmnet_data0", "ccmni1", "tun0", "wg0", "hnc_nonexistent_ap99"} {
			if defaultNeighIfaceReady(badIface) {
				t.Fatalf("defaultNeighIfaceReady(%q) = true, want false", badIface)
			}
		}
	})

	t.Run("disabled_flag_and_sim_active_short_circuit", func(t *testing.T) {
		hncDir := t.TempDir()
		for _, sub := range []string{"run", "data"} {
			_ = os.MkdirAll(filepath.Join(hncDir, sub), 0o755)
		}
		var nowMtx sync.Mutex
		curNow := time.Unix(1795249100, 0)
		var dumpCalls atomic.Int32
		installNeighTestHooks(t, &curNow, &nowMtx, 6, func(ifindex int) ([]neigh.Entry, error) {
			dumpCalls.Add(1)
			return []neigh.Entry{
				{IfIndex: 6, IP: net.ParseIP("192.168.43.55"), MAC: "aa:bb:cc:55:66:77", State: neigh.NUDReachable},
			}, nil
		})
		_ = os.WriteFile(filepath.Join(hncDir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644)
		_ = os.WriteFile(filepath.Join(hncDir, "run", "neigh_fallback.disabled"), []byte("1\n"), 0o644)

		srv := &server{hncDir: hncDir}
		devicesPath := filepath.Join(hncDir, "data", "devices.json")
		if got := srv.mergeReadonlyNeighFallback(devicesPath, map[string]any{}, curNow.Unix()); len(got) != 0 || dumpCalls.Load() != 0 {
			t.Fatalf("disabled flag did not block fallback: got=%#v dumpCalls=%d", got, dumpCalls.Load())
		}

		_ = os.Remove(filepath.Join(hncDir, "run", "neigh_fallback.disabled"))
		simFor(hncDir).hasDev.Store(true)
		t.Cleanup(func() { simFor(hncDir).hasDev.Store(false) })
		if got := srv.mergeReadonlyNeighFallback(devicesPath, map[string]any{}, curNow.Unix()); len(got) != 0 || dumpCalls.Load() != 0 {
			t.Fatalf("simActive did not block fallback: got=%#v dumpCalls=%d", got, dumpCalls.Load())
		}
	})
}

func TestNeighFallback_StaleConfirmedAgoAndRegPrune(t *testing.T) {
	t.Run("stale_180s_never_resurrected_and_fresh_stale_uses_confirmed_ago", func(t *testing.T) {
		hncDir := t.TempDir()
		for _, sub := range []string{"run", "data"} {
			_ = os.MkdirAll(filepath.Join(hncDir, sub), 0o755)
		}

		var nowMtx sync.Mutex
		curNow := time.Unix(1795250000, 0)
		nowSec := curNow.Unix()

		installNeighTestHooks(t, &curNow, &nowMtx, 8, func(ifindex int) ([]neigh.Entry, error) {
			return []neigh.Entry{
				{
					IfIndex:      8,
					IP:           net.ParseIP("192.168.43.180"),
					MAC:          "aa:bb:cc:01:01:80",
					State:        neigh.NUDStale,
					HasCacheInfo: true,
					ConfirmedAgo: 180 * time.Second,
				},
				{
					IfIndex:      8,
					IP:           net.ParseIP("192.168.43.181"),
					MAC:          "aa:bb:cc:01:00:90",
					State:        neigh.NUDStale,
					HasCacheInfo: true,
					ConfirmedAgo: 90 * time.Second,
				},
				{
					IfIndex:      8,
					IP:           net.ParseIP("192.168.43.35"),
					MAC:          "aa:bb:cc:01:00:35",
					State:        neigh.NUDStale,
					HasCacheInfo: true,
					ConfirmedAgo: 35 * time.Second,
				},
				{
					IfIndex:      8,
					IP:           net.ParseIP("192.168.43.36"),
					MAC:          "aa:bb:cc:01:00:36",
					State:        neigh.NUDStale,
					HasCacheInfo: true,
					ConfirmedAgo: 40 * time.Second,
				},
				{
					IfIndex: 8,
					IP:      net.ParseIP("192.168.43.37"),
					MAC:     "aa:bb:cc:01:00:37",
					State:   neigh.NUDProbe,
				},
			}, nil
		})

		_ = os.WriteFile(filepath.Join(hncDir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644)
		devicesPath := filepath.Join(hncDir, "data", "devices.json")

		existing := map[string]any{
			"aa:bb:cc:01:01:80": map[string]any{
				"ip":         "192.168.43.180",
				"mac":        "aa:bb:cc:01:01:80",
				"first_seen": float64(nowSec - 600),
				"last_seen":  float64(nowSec - 300),
			},
			"aa:bb:cc:01:00:36": map[string]any{
				"ip":         "192.168.43.36",
				"mac":        "aa:bb:cc:01:00:36",
				"first_seen": float64(nowSec - 120),
				"last_seen":  float64(nowSec - 10),
			},
		}

		srv := &server{hncDir: hncDir}
		merged := srv.mergeReadonlyNeighFallback(devicesPath, existing, nowSec)

		if _, resurrected := merged["aa:bb:cc:01:00:90"]; resurrected {
			t.Fatalf("90s NUD_STALE entry must not be resurrected: %#v", merged["aa:bb:cc:01:00:90"])
		}
		offline180 := merged["aa:bb:cc:01:01:80"].(map[string]any)
		if offline180["last_seen"] != float64(nowSec-300) {
			t.Fatalf("180s NUD_STALE entry resurrected offline device: got last_seen=%v want %v", offline180["last_seen"], float64(nowSec-300))
		}

		freshStale, ok := merged["aa:bb:cc:01:00:35"].(map[string]any)
		if !ok || freshStale["last_seen"] != float64(nowSec-35) {
			t.Fatalf("35s NUD_STALE last_seen mismatch: %#v, want %v", freshStale, float64(nowSec-35))
		}

		newerExisting := merged["aa:bb:cc:01:00:36"].(map[string]any)
		if newerExisting["last_seen"] != float64(nowSec-10) {
			t.Fatalf("existing newer last_seen regressed: got %v want %v", newerExisting["last_seen"], float64(nowSec-10))
		}

		probeDev, ok := merged["aa:bb:cc:01:00:37"].(map[string]any)
		if !ok || probeDev["last_seen"] != float64(nowSec) {
			t.Fatalf("NUD_PROBE active entry last_seen mismatch: %#v, want %v", probeDev, float64(nowSec))
		}
	})

	t.Run("reg_prunes_expired_entries_beyond_16", func(t *testing.T) {
		var nowMtx sync.Mutex
		curNow := time.Unix(1795251000, 0)
		installNeighTestHooks(t, &curNow, &nowMtx, 9, func(ifindex int) ([]neigh.Entry, error) {
			return nil, nil
		})
		neighFallbackRegMtx.Lock()
		neighFallbackReg = make(map[string]*neighFallbackDirState)
		neighFallbackRegMtx.Unlock()

		base := t.TempDir()
		for i := 0; i < neighFallbackRegPruneAt; i++ {
			st := getNeighFallbackDirState(filepath.Join(base, "dir_"+strconv.Itoa(i)))
			st.mtx.Lock()
			st.armedUntil = curNow.Add(-1 * time.Second)
			st.mtx.Unlock()
		}
		neighFallbackRegMtx.Lock()
		beforePrune := len(neighFallbackReg)
		neighFallbackRegMtx.Unlock()
		if beforePrune != neighFallbackRegPruneAt {
			t.Fatalf("expected %d entries before watermark prune, got %d", neighFallbackRegPruneAt, beforePrune)
		}

		// 第 17 个目录跨过 >= 16 水位线: 前 16 个过期目录全量回收, 仅剩刚注册的 active_dir
		_ = getNeighFallbackDirState(filepath.Join(base, "active_dir"))
		neighFallbackRegMtx.Lock()
		n := len(neighFallbackReg)
		neighFallbackRegMtx.Unlock()
		if n != 1 {
			t.Fatalf("neighFallbackReg did not prune expired dirs at watermark: len=%d, want 1", n)
		}
	})
}
