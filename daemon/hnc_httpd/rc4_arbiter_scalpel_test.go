package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestRC4Atomic64StructAlignment(t *testing.T) {
	var (
		zArb RootShaperArbiter
		zThm thermoCruiseEngine
		zSc  flowScalpelEngine
	)
	checks := []struct {
		name   string
		offset uintptr
	}{
		{"RootShaperArbiter.evalTotal", unsafe.Offsetof(zArb.evalTotal)},
		{"RootShaperArbiter.applyTotal", unsafe.Offsetof(zArb.applyTotal)},
		{"RootShaperArbiter.floorClamps", unsafe.Offsetof(zArb.floorClamps)},
		{"RootShaperArbiter.recoverySteps", unsafe.Offsetof(zArb.recoverySteps)},
		{"RootShaperArbiter.lastApplyUnix", unsafe.Offsetof(zArb.lastApplyUnix)},
		{"thermoCruiseEngine.evalCount", unsafe.Offsetof(zThm.evalCount)},
		{"thermoCruiseEngine.effectiveStage", unsafe.Offsetof(zThm.effectiveStage)},
		{"thermoCruiseEngine.sensorFaultCount", unsafe.Offsetof(zThm.sensorFaultCount)},
		{"flowScalpelEngine.seqGen", unsafe.Offsetof(zSc.seqGen)},
		{"flowScalpelEngine.cutTotal", unsafe.Offsetof(zSc.cutTotal)},
		{"flowScalpelEngine.guardBlocked", unsafe.Offsetof(zSc.guardBlocked)},
	}
	for _, c := range checks {
		if c.offset%8 != 0 {
			t.Fatalf("%s offset=%d is NOT 8-byte aligned for 32-bit ARM", c.name, c.offset)
		}
	}
}

func TestThermoRC4SensorAdaptiveUnitsSentinelsAndCircuitBreaker(t *testing.T) {
	psPath := "/sys/class/power_supply/battery/temp"
	tzPath := "/sys/class/thermal/thermal_zone1/temp"

	// 1. 三档自适应单位换算与冬天低温兼容
	unitCases := []struct {
		path string
		raw  string
		want float64
	}{
		{psPath, "42000", 42.0},
		{psPath, "420", 42.0},
		{psPath, "85", 8.5},
		{psPath, "36.5", 36.5},
		{tzPath, "42000", 42.0},
		{tzPath, "420", 42.0},
		{tzPath, "42", 42.0},
	}
	for _, tc := range unitCases {
		got, reason, ok := parseSysfsTempCelsiusDetail(tc.path, tc.raw)
		if !ok || reason != "" || got != tc.want {
			t.Fatalf("parseSysfsTempCelsiusDetail(%s, %q) = (%.2f, %q, %v), want (%.2f, \"\", true)",
				tc.path, tc.raw, got, reason, ok, tc.want)
		}
	}

	// 2. 驱动坏值/哨兵值拦截
	sentinels := []struct {
		path string
		raw  string
	}{
		{psPath, "2147483647"},
		{psPath, "-2147483648"},
		{psPath, "125000"},
		{psPath, "127000"},
		{psPath, "255000"},
		{psPath, "-273000"},
		{psPath, "-40000"},
		{psPath, "-400"},
		{tzPath, "0"},
	}
	for _, sc := range sentinels {
		if _, reason, ok := parseSysfsTempCelsiusDetail(sc.path, sc.raw); ok || reason != ThermoReasonSensorSentinel {
			t.Fatalf("expected sentinel rejection for (%s, %q), got reason=%q ok=%v", sc.path, sc.raw, reason, ok)
		}
	}

	// 3. 物理合理区间边界: 电池 [-20, 85]°C, thermal_zone [-20, 100]°C
	if _, reason, ok := parseSysfsTempCelsiusDetail(psPath, "900"); ok || reason != ThermoReasonSensorOutOfRange {
		t.Fatalf("expected battery 90.0C out_of_range, got reason=%q ok=%v", reason, ok)
	}
	if got, reason, ok := parseSysfsTempCelsiusDetail(tzPath, "92000"); !ok || reason != "" || got != 92.0 {
		t.Fatalf("expected thermal_zone 92.0C valid, got %.2f reason=%q ok=%v", got, reason, ok)
	}
	if _, reason, ok := parseSysfsTempCelsiusDetail(tzPath, "105000"); ok || reason != ThermoReasonSensorOutOfRange {
		t.Fatalf("expected thermal_zone 105.0C out_of_range, got reason=%q ok=%v", reason, ok)
	}

	// 4. 传感器故障熔断立即释放活跃二阶温控压速并累加 sensor_fault_count
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"), []byte(`{"iface":"wlan2"}`), 0o644)

	sysRoot := filepath.Join(dir, "sys_ps")
	batDir := filepath.Join(sysRoot, "battery")
	_ = os.MkdirAll(batDir, 0o755)
	_ = os.WriteFile(filepath.Join(batDir, "temp"), []byte("465\n"), 0o644)
	_ = os.WriteFile(filepath.Join(batDir, "capacity"), []byte("75\n"), 0o644)
	_ = os.WriteFile(filepath.Join(batDir, "status"), []byte("Discharging\n"), 0o644)

	srv := &server{hncDir: dir}
	arb := srv.shaperArbiter()
	arb.mu.Lock()
	arb.applyHook = func(iface string, active bool, downKbps, upKbps int, prevActive bool) error {
		return nil
	}
	arb.mu.Unlock()

	eng := srv.v6State().thermo
	eng.sysfsRoot = sysRoot
	now := time.Unix(1771000000, 0)

	rdHot := eng.sampleBattery()
	stHot := eng.Evaluate(now, rdHot, false)
	if stHot["effective_stage"].(int) != 2 {
		t.Fatalf("expected stage 2 at 46.5C, got %+v", stHot)
	}
	snapThrottled := arb.Snapshot()
	if !snapThrottled.ThermoStage2Active || snapThrottled.EffectiveDownMbps != 40.0 || snapThrottled.EffectiveUpMbps != 15.0 {
		t.Fatalf("expected arbiter stage2 soft cap 40/15 Mbps, got %+v", snapThrottled)
	}

	// 注入驱动哨兵坏值: 必须累加 sensor_fault_count 并立即熔断释放温控限速
	_ = os.WriteFile(filepath.Join(batDir, "temp"), []byte("2147483647\n"), 0o644)
	rdFault := eng.sampleBattery()
	stFault := eng.Evaluate(now.Add(5*time.Second), rdFault, false)
	if rdFault.Available || rdFault.ReasonCode != ThermoReasonSensorSentinel {
		t.Fatalf("expected sensor_sentinel reading, got %+v", rdFault)
	}
	if stFault["effective_stage"].(int) != 0 || stFault["sensor_fault_count"].(uint64) < 1 {
		t.Fatalf("expected immediate circuit-breaker stage 0 and fault count >= 1, got %+v", stFault)
	}
	snapReleased := arb.Snapshot()
	if snapReleased.ThermoStage2Active || snapReleased.ThermoRecovering || snapReleased.EffectiveDownKbps != 0 {
		t.Fatalf("expected arbiter immediate release on sensor fault, got %+v", snapReleased)
	}
}

func readTestBatterySysfs(sysfsRoot string) ThermoBatteryReading {
	eng := newThermoCruiseEngine(nil)
	eng.sysfsRoot = sysfsRoot
	return eng.ReadBatteryFromSysfs()
}

func TestThermoRC4HeterogeneousFallbackBypassAndPowerRelax(t *testing.T) {
	// 1. 异构路径回退: battery 缺失 -> bms/temp -> BAT0/temp -> thermal_zone*/temp (chg_therm)
	base := t.TempDir()
	psBms := filepath.Join(base, "case_bms", "power_supply")
	_ = os.MkdirAll(filepath.Join(psBms, "bms"), 0o755)
	_ = os.WriteFile(filepath.Join(psBms, "bms", "temp"), []byte("435\n"), 0o644)
	rdBms := readTestBatterySysfs(psBms)
	if !rdBms.Available || rdBms.TempC != 43.5 {
		t.Fatalf("bms fallback failed: %+v", rdBms)
	}

	psBat0 := filepath.Join(base, "case_bat0", "power_supply")
	_ = os.MkdirAll(filepath.Join(psBat0, "BAT0"), 0o755)
	_ = os.WriteFile(filepath.Join(psBat0, "BAT0", "temp"), []byte("44200\n"), 0o644)
	rdBat0 := readTestBatterySysfs(psBat0)
	if !rdBat0.Available || rdBat0.TempC != 44.2 {
		t.Fatalf("BAT0 fallback failed: %+v", rdBat0)
	}

	caseTz := filepath.Join(base, "case_tz")
	psEmpty := filepath.Join(caseTz, "power_supply")
	tzRoot := filepath.Join(caseTz, "thermal")
	_ = os.MkdirAll(psEmpty, 0o755)
	_ = os.MkdirAll(filepath.Join(tzRoot, "thermal_zone0"), 0o755)
	_ = os.MkdirAll(filepath.Join(tzRoot, "thermal_zone2"), 0o755)
	_ = os.WriteFile(filepath.Join(tzRoot, "thermal_zone0", "type"), []byte("soc_max\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tzRoot, "thermal_zone0", "temp"), []byte("75000\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tzRoot, "thermal_zone2", "type"), []byte("chg_therm\n"), 0o644)
	_ = os.WriteFile(filepath.Join(tzRoot, "thermal_zone2", "temp"), []byte("45800\n"), 0o644)
	rdTz := readTestBatterySysfs(psEmpty)
	if !rdTz.Available || rdTz.TempC != 45.8 {
		t.Fatalf("thermal_zone chg_therm fallback failed: %+v", rdTz)
	}

	// 2. 旁路供电识别 (usb/online=1 + Not charging: 外部供电不误触发低电量巡航, 且不误判为快充自发热; online=0 + 残留 Charging 不误豁免)
	psBypass := filepath.Join(base, "case_bypass", "power_supply")
	_ = os.MkdirAll(filepath.Join(psBypass, "battery"), 0o755)
	_ = os.MkdirAll(filepath.Join(psBypass, "usb"), 0o755)
	_ = os.WriteFile(filepath.Join(psBypass, "battery", "temp"), []byte("360\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psBypass, "battery", "capacity"), []byte("15\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psBypass, "battery", "status"), []byte("Not charging\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psBypass, "usb", "online"), []byte("1\n"), 0o644)

	eng := newThermoCruiseEngine(nil)
	rdByLow := readTestBatterySysfs(psBypass)
	if !rdByLow.ChargerOnline || !rdByLow.IsBypassSupply || rdByLow.IsCharging {
		t.Fatalf("expected bypass supply detected as ChargerOnline=true, IsBypassSupply=true, IsCharging=false, got %+v", rdByLow)
	}
	stByLow := eng.Evaluate(time.Now(), rdByLow, false)
	if stByLow["low_battery_cruise"] != false || stByLow["effective_stage"].(int) != 0 {
		t.Fatalf("expected external bypass supply to suppress low-battery cruise at 15%%, got %+v", stByLow)
	}

	// 旁路供电下若真烧到 46.8C (SoC/射频实热而非快充发热): 不误豁免二阶温控
	_ = os.WriteFile(filepath.Join(psBypass, "battery", "temp"), []byte("468\n"), 0o644)
	rdByHot := readTestBatterySysfs(psBypass)
	stByHot := eng.Evaluate(time.Now().Add(time.Second), rdByHot, false)
	if stByHot["effective_stage"].(int) != 2 || stByHot["stage2_exempt"] != false {
		t.Fatalf("expected bypass supply at 46.8C NOT mistaken for fast-charge heat, got %+v", stByHot)
	}

	// 真实快充 (usb/online=1 + Charging) -> 豁免二阶压速为 stage1; 拔掉充电器 (usb/online=0 + 残留 Charging) -> 不误豁免
	_ = os.WriteFile(filepath.Join(psBypass, "battery", "status"), []byte("Charging\n"), 0o644)
	rdChg := readTestBatterySysfs(psBypass)
	stChg := eng.Evaluate(time.Now().Add(2*time.Second), rdChg, false)
	if !rdChg.IsCharging || stChg["effective_stage"].(int) != 1 || stChg["stage2_exempt"] != true {
		t.Fatalf("expected real charging (usb/online=1 + Charging) to exempt stage2, got %+v", stChg)
	}
	_ = os.WriteFile(filepath.Join(psBypass, "usb", "online"), []byte("0\n"), 0o644)
	rdUnplug := readTestBatterySysfs(psBypass)
	if rdUnplug.IsCharging {
		t.Fatalf("expected usb/online=0 to override stale Charging status, got %+v", rdUnplug)
	}
	stUnplug := eng.Evaluate(time.Now().Add(3*time.Second), rdUnplug, false)
	if stUnplug["effective_stage"].(int) != 2 {
		t.Fatalf("expected unplugged device at 46.8C to enter stage2, got %+v", stUnplug)
	}

	// 3. Stage 1 真实联动 power_sched.go 非关键循环翻倍降频
	act := Activity{
		Known:         true,
		Level:         lvlActive,
		HotspotActive: true,
		ClientsOnline: 2,
		ScreenOn:      true,
		ScreenKnown:   true,
	}
	dBase, _ := powerInterval("mac_merge", act, loopFlags{})
	dRelax, reasonRelax := powerInterval("mac_merge", act, loopFlags{ThermoStage1: true})
	if dBase != 30*time.Second || dRelax != 60*time.Second || !strings.Contains(reasonRelax, "温控巡航") {
		t.Fatalf("expected mac_merge 30s -> 60s under ThermoStage1, got base=%v relax=%v (%s)", dBase, dRelax, reasonRelax)
	}
	arBase, _ := powerInterval("autorate", act, loopFlags{})
	arRelax, _ := powerInterval("autorate", act, loopFlags{ThermoStage1: true})
	if arBase != 2*time.Second || arRelax != 4*time.Second {
		t.Fatalf("expected autorate 2s -> 4s under ThermoStage1, got base=%v relax=%v", arBase, arRelax)
	}
	critBase, _ := powerInterval("limit_policy", act, loopFlags{ThermoStage1: true})
	if critBase != time.Minute {
		t.Fatalf("critical loop limit_policy must NOT relax, got %v", critBase)
	}
}

func TestRC4RootShaperArbiterFloorSmoothRecoveryAndRestore(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"run", "data", "etc/dpi_rules.d"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"), []byte(`{"iface":"wlan2"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "devices.json"), []byte(`{"devices":[]}`), 0o644)

	// 用户静态基准写入 data/rules.json: 100Mbps 下行 / 50Mbps 上行
	rulesPath := filepath.Join(dir, "data", "rules.json")
	writeRules := func(enabled bool, downStr, upStr string) {
		raw := fmt.Sprintf(`{"global_shaper_enabled":%v,"global_shaper_down":%q,"global_shaper_up":%q}`, enabled, downStr, upStr)
		if err := os.WriteFile(rulesPath, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeRules(true, "100mbit", "50mbit")

	srv := newServer(dir)
	arb := srv.shaperArbiter()
	var appliedHistory []string
	arb.mu.Lock()
	arb.applyHook = func(iface string, active bool, downKbps, upKbps int, prevActive bool) error {
		appliedHistory = append(appliedHistory, fmt.Sprintf("%s:%v:%d:%d", iface, active, downKbps, upKbps))
		return nil
	}
	arb.mu.Unlock()

	now := time.Unix(1771005000, 0)

	// 1. Autorate ApplyConfig 绝不覆写 data/rules.json 的用户静态基准
	srv.autorate.bindServer(srv)
	arResp := srv.autorate.ApplyConfig(autorateConfig{
		Enabled:     true,
		DownMinMbps: 20,
		DownMaxMbps: 100,
		UpMinMbps:   10,
		UpMaxMbps:   40,
		RTTDeltaMs:  35,
	}, "wlan2")
	if !arResp.OK {
		t.Fatalf("autorate ApplyConfig failed: %+v", arResp)
	}
	rawRulesAfterAutorate, _ := os.ReadFile(rulesPath)
	if !strings.Contains(string(rawRulesAfterAutorate), `"100mbit"`) || !strings.Contains(string(rawRulesAfterAutorate), `"50mbit"`) {
		t.Fatalf("autorate overwrote user static shaper in rules.json: %s", string(rawRulesAfterAutorate))
	}
	snap1 := arb.Snapshot()
	if snap1.EffectiveDownMbps != 72.0 || snap1.EffectiveUpMbps != 30.0 || snap1.StaticDownMbps != 100.0 {
		t.Fatalf("expected min(100,72)=72 / min(50,30)=30, got %+v", snap1)
	}

	// 关闭后台 autorate 控制器被动覆盖，直接测试仲裁器三路输入组合
	srv.autorate.DisableFromStaticShaper()

	// 2. 双自动化叠加压速触及全局地板保护 (5.0 Mbps 下行 / 2.0 Mbps 上行)
	_, _ = arb.UpdateAutorate(now, "wlan2", true, 3.0, 1.0, false)
	snapFloor := arb.UpdateThermoStage2(now, true, 47.2, false)
	if snapFloor.EffectiveDownMbps != ArbiterAutoFloorDownMbps || snapFloor.EffectiveUpMbps != ArbiterAutoFloorUpMbps {
		t.Fatalf("expected global auto floor 5.0/2.0 Mbps, got down=%.2f up=%.2f",
			snapFloor.EffectiveDownMbps, snapFloor.EffectiveUpMbps)
	}
	if !snapFloor.FloorClamped || arb.floorClamps.Load() == 0 {
		t.Fatalf("expected FloorClamped=true and floorClamps>0, got %+v", snapFloor)
	}

	// 3. 用户手动静态设置低于地板 (3.0 / 1.0 Mbps) 时尊重用户显式配置
	writeRules(true, "3mbit", "1mbit")
	_ = arb.SetStaticBaseline(now, "wlan2", true, 3.0, 1.0, false)
	snapManualLow := arb.Snapshot()
	if snapManualLow.EffectiveDownMbps != 3.0 || snapManualLow.EffectiveUpMbps != 1.0 {
		t.Fatalf("expected manual low static baseline 3.0/1.0 respected, got %.2f/%.2f",
			snapManualLow.EffectiveDownMbps, snapManualLow.EffectiveUpMbps)
	}

	// 4. Stage 2 按用户静态基准 60% 压顶 (100/50 -> 60/30) + 退档后每轮 +20% 平滑回升直至完全释放
	_, _ = arb.UpdateAutorate(now, "wlan2", false, 0, 0, false)
	writeRules(true, "100mbit", "50mbit")
	_ = arb.SetStaticBaseline(now, "wlan2", true, 100.0, 50.0, false)
	snapS2 := arb.UpdateThermoStage2(now, true, 46.5, false)
	if snapS2.EffectiveDownMbps != 60.0 || snapS2.EffectiveUpMbps != 30.0 {
		t.Fatalf("expected 60%% of static 100/50 => 60/30 Mbps, got %.2f/%.2f",
			snapS2.EffectiveDownMbps, snapS2.EffectiveUpMbps)
	}
	if len(snapS2.ThrottleSources) == 0 || !strings.Contains(snapS2.ActiveLimiterReason, "温控") {
		t.Fatalf("expected Chinese limiter reason & throttle_sources, got %+v", snapS2)
	}

	// 验证 /api/live 顶层暴露非 nil throttle_sources 与中文 active_limiter_reason
	liveRec := httptest.NewRecorder()
	liveReq := httptest.NewRequest(http.MethodGet, "/api/live", nil)
	srv.apiLive(liveRec, liveReq)
	if liveRec.Code != http.StatusOK {
		t.Fatalf("GET /api/live failed: %d %s", liveRec.Code, liveRec.Body.String())
	}
	var liveBody map[string]any
	if err := json.Unmarshal(liveRec.Body.Bytes(), &liveBody); err != nil {
		t.Fatalf("unmarshal /api/live: %v", err)
	}
	tsSlice, okTS := liveBody["throttle_sources"].([]any)
	reasonStr, _ := liveBody["active_limiter_reason"].(string)
	if !okTS || len(tsSlice) == 0 || !strings.Contains(reasonStr, "温控") {
		t.Fatalf("expected /api/live throttle_sources & Chinese active_limiter_reason, got sources=%v reason=%q",
			liveBody["throttle_sources"], reasonStr)
	}

	// 退回 Stage 1: 第 1 轮平滑回升 *1.20 -> 72 / 36 Mbps
	snapRec1 := arb.UpdateThermoStage2(now.Add(10*time.Second), false, 41.0, false)
	if !snapRec1.ThermoRecovering || snapRec1.EffectiveDownMbps != 72.0 || snapRec1.EffectiveUpMbps != 36.0 {
		t.Fatalf("expected round 1 smooth recovery 72/36 Mbps, got %+v", snapRec1)
	}
	// 第 2 轮 *1.20 -> 86.4 / 43.2 Mbps
	snapRec2 := arb.UpdateThermoStage2(now.Add(20*time.Second), false, 41.0, false)
	if !snapRec2.ThermoRecovering || snapRec2.EffectiveDownMbps != 86.4 || snapRec2.EffectiveUpMbps != 43.2 {
		t.Fatalf("expected round 2 smooth recovery 86.4/43.2 Mbps, got %+v", snapRec2)
	}
	// 第 3 轮 *1.20 >= 100/50 -> 触顶完全释放温控软顶回到用户静态基准 100/50 Mbps
	snapRec3 := arb.UpdateThermoStage2(now.Add(30*time.Second), false, 38.0, false)
	if snapRec3.ThermoRecovering || snapRec3.ThermoStage2Active || snapRec3.EffectiveDownMbps != 100.0 || snapRec3.EffectiveUpMbps != 50.0 {
		t.Fatalf("expected full release back to static 100/50 Mbps, got %+v", snapRec3)
	}

	// 5. NativeFullRestoreV6 重建后通过 replayRootShaperArbiterAfterRestore 强制重放仲裁速率
	beforeCnt := len(appliedHistory)
	srv.replayRootShaperArbiterAfterRestore("wlan2")
	if len(appliedHistory) <= beforeCnt {
		t.Fatalf("expected replayRootShaperArbiterAfterRestore to force re-apply, history=%v", appliedHistory)
	}

	// 6. /api/vector_sync 扩展注册检查
	exts := collectVectorSyncProviders(srv)
	if _, ok := exts["arbiter"]; !ok {
		t.Fatalf("expected /api/vector_sync extensions.arbiter registered, got keys=%v", exts)
	}
}

func TestRC4VectorExpressLeashMangleIsolationAndMultiIfaceRealRules(t *testing.T) {
	// 1. VectorExpress 与 UpdateLeash 双栈 *mangle 掩码隔离审计 (严禁触碰低 16 位 0x0000ffff)
	devIPs := map[string][]string{
		"aa:bb:cc:dd:ee:20": {"192.168.43.20", "fd00::20"},
		"aa:bb:cc:dd:ee:30": {"192.168.43.30", "fd00::30"},
	}
	expV4, expV6 := BuildVectorExpressManglePayloads(true, []string{"aa:bb:cc:dd:ee:20"}, devIPs)
	leashV4, leashV6 := BuildUpdateLeashManglePayloads([]UpdateLeashSession{
		{MAC: "aa:bb:cc:dd:ee:30", SrcIP: "192.168.43.30", DstIP: "203.0.113.10", State: "leashed"},
		{MAC: "aa:bb:cc:dd:ee:30", SrcIP: "fd00::30", DstIP: "2001:db8::10", State: "leashed"},
	}, devIPs)
	for name, payload := range map[string]string{
		"express_v4": expV4,
		"express_v6": expV6,
		"leash_v4":   leashV4,
		"leash_v6":   leashV6,
	} {
		if !strings.HasPrefix(payload, "*mangle\n") {
			t.Fatalf("%s must target *mangle table, got:\n%s", name, payload)
		}
		for _, tok := range strings.Fields(payload) {
			if !strings.HasPrefix(tok, "0x") {
				continue
			}
			parts := strings.Split(tok, "/")
			for _, hexPart := range parts {
				val, err := strconv.ParseUint(strings.TrimPrefix(hexPart, "0x"), 16, 32)
				if err != nil {
					t.Fatalf("%s invalid hex mark/mask %q: %v", name, tok, err)
				}
				if val&0x0000ffff != 0 {
					t.Fatalf("%s polluted low-16-bit device slot mask in %q (0x%08x)", name, tok, val)
				}
			}
		}
	}
	// Express 必须豁免已被 UpdateLeash 打上 0x03000000 的流
	if !strings.Contains(expV4, "-m mark ! --mark 0x03000000/0x03000000") ||
		!strings.Contains(expV6, "-m mark ! --mark 0x03000000/0x03000000") {
		t.Fatalf("express mangle chain must exempt leashed 0x03000000 flows:\n%s\n%s", expV4, expV6)
	}

	// 2. 根速率变更实时联动 VectorExpress 重算后台压制顶限 (75%) 与对账摘要更新
	dir := setupNativeTierTestEnv(t, "wlan2")
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"),
		[]byte(`{"global_shaper_enabled":true,"global_shaper_down":"80mbit","global_shaper_up":"30mbit"}`), 0o644)
	srv := &server{
		hncDir:    dir,
		jsonCache: newJSONFileCache(),
	}
	arb := srv.shaperArbiter()
	arb.mu.Lock()
	arb.applyHook = func(iface string, active bool, downKbps, upKbps int, prevActive bool) error {
		return nil
	}
	arb.mu.Unlock()

	ve := srv.v6State().express
	var (
		bgMu         sync.Mutex
		syncedBgCeil []int
	)
	ve.dpEnabledFn = func(string) bool { return true }
	ve.mangleApplyFn = func(bool, string) error { return nil }
	ve.invalidateFn = func(string, string) {}
	ve.nativeApplyFn = func(_ string, enable bool, _ uint32, bgCeilKbps int) error {
		if enable {
			bgMu.Lock()
			syncedBgCeil = append(syncedBgCeil, bgCeilKbps)
			bgMu.Unlock()
		}
		return nil
	}

	lastBgCeil := func() int {
		bgMu.Lock()
		defer bgMu.Unlock()
		if len(syncedBgCeil) == 0 {
			return 0
		}
		return syncedBgCeil[len(syncedBgCeil)-1]
	}

	_ = arb.SetStaticBaseline(time.Now(), "wlan2", true, 80.0, 30.0, false)
	ve.Step(time.Now(), []VectorExpressDeviceSignal{
		{MAC: "aa:bb:cc:dd:ee:20", TrafficType: "gaming", Confidence: 0.96, ActiveDstIPs: 3},
	})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && lastBgCeil() != 68000 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := lastBgCeil(); got != 68000 {
		t.Fatalf("expected VectorExpress dynamically synced with 85%% of 80Mbps (68000kbps), got %d (%v)", got, syncedBgCeil)
	}

	arb.UpdateThermoStage2(time.Now(), true, 46.8, false) // 60% of 80Mbps = 48Mbps -> 85% = 40800kbps
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && lastBgCeil() != 40800 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := lastBgCeil(); got != 40800 {
		t.Fatalf("expected VectorExpress updated to 40800kbps on Stage2 root rate change, got %d (%v)", got, syncedBgCeil)
	}

	// 3. v6_multi_iface.go 真实读取 ip -4 rule show 与读取失败诚实降级告警 (绝不传 nil 假绿灯)
	origRuleReader := v6ReadLiveIPRulesFn
	t.Cleanup(func() { v6ReadLiveIPRulesFn = origRuleReader })

	vpnInputs := []V6IfaceProbeInput{
		{Name: "wlan2", OperUp: true, Carrier: true, IPv4CIDRs: []string{"192.168.43.1/24"}},
		{Name: "tun0", OperUp: true, Carrier: true, MTU: 1500, IPv4CIDRs: []string{"10.8.0.2/24"}},
	}

	v6ReadLiveIPRulesFn = func() ([]string, string, bool) {
		return nil, "ip_rule_exec_failed", false
	}
	snapFail := analyzeMultiInterfacesWithLiveRules(vpnInputs, "wlan2")
	if snapFail.Tun0Guard.IPRulesKnown || !snapFail.Tun0Guard.LoopRiskDetected || snapFail.Tun0Guard.IPRulesReason != "ip_rule_exec_failed" {
		t.Fatalf("expected honest LoopRiskDetected=true & IPRulesKnown=false when ip rule fails, got %+v", snapFail.Tun0Guard)
	}

	v6ReadLiveIPRulesFn = func() ([]string, string, bool) {
		return []string{
			"0:\tfrom all lookup local",
			"8960:\tfrom all to 192.168.43.0/24 lookup main",
			"13000:\tfrom all uidrange 0-99999 lookup tun0",
		}, "", true
	}
	snapBypass := analyzeMultiInterfacesWithLiveRules(vpnInputs, "wlan2")
	if !snapBypass.Tun0Guard.IPRulesKnown || snapBypass.Tun0Guard.LoopRiskDetected {
		t.Fatalf("expected IPRulesKnown=true & LoopRiskDetected=false when subnet bypass rule exists, got %+v", snapBypass.Tun0Guard)
	}
}

func buildTestNetlinkAckFrame(seq uint32, errno int32) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[0:4], 20)
	binary.LittleEndian.PutUint16(msg[4:6], scalpelNlMsgError)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(-errno))
	return msg
}

func TestScalpelRC4RulesGuardRehookDedupCapReverseCtAndZeroWakeups(t *testing.T) {
	// 1. r5s (! --syn) 与 r15m (优先 ClientMAC + NEW,INVALID, 缺省回退 SrcIP) 双栈载荷校验
	rules := []ScalpelActiveRule{
		{
			ID:         "tcp_rst",
			Mode:       "reset_5s",
			IsIPv6:     false,
			MatchSport: true,
			Tuple:      ScalpelTuple{Proto: "tcp", SrcIP: "192.168.43.88", Sport: 51234, DstIP: "198.51.100.20", Dport: 443},
		},
		{
			ID:         "frz_mac",
			Mode:       "freeze_15m",
			IsIPv6:     false,
			ClientMAC:  "AA:BB:CC:DD:EE:01",
			MatchSport: false,
			Tuple:      ScalpelTuple{Proto: "tcp", SrcIP: "192.168.43.88", Sport: 51234, DstIP: "198.51.100.20", Dport: 443},
		},
		{
			ID:         "frz_ip_v6",
			Mode:       "freeze_15m",
			IsIPv6:     true,
			MatchSport: false,
			Tuple:      ScalpelTuple{Proto: "udp", SrcIP: "fd00::88", Sport: 53000, DstIP: "2001:db8::99", Dport: 3478},
		},
	}
	v4Payload := buildScalpelRestorePayload(false, rules)
	if !strings.Contains(v4Payload, "-A HNC_SCALPEL -p tcp ! --syn -s 192.168.43.88 -d 198.51.100.20 --sport 51234 --dport 443 -j REJECT --reject-with tcp-reset") {
		t.Fatalf("missing ! --syn in TCP r5s rule:\n%s", v4Payload)
	}
	if !strings.Contains(v4Payload, "-A HNC_SCALPEL -m mac --mac-source aa:bb:cc:dd:ee:01 -d 198.51.100.20 -p tcp --dport 443 -m conntrack --ctstate NEW,INVALID -j REJECT --reject-with tcp-reset") {
		t.Fatalf("missing MAC + NEW,INVALID in r15m rule:\n%s", v4Payload)
	}
	v6Payload := buildScalpelRestorePayload(true, rules)
	if !strings.Contains(v6Payload, "-A HNC_SCALPEL -s fd00::88 -d 2001:db8::99 -p udp --dport 3478 -m conntrack --ctstate NEW,INVALID -j REJECT --reject-with icmp6-port-unreachable") {
		t.Fatalf("missing SrcIP fallback + NEW,INVALID in IPv6 r15m rule:\n%s", v6Payload)
	}

	// 2. 共享 CDN / 公共 DNS / 核心端口 53/853/123 拒绝 15m 冻结，但允许 cut_once 精确单流秒斩
	dir := setupNativeTierTestEnv(t, "wlan2")
	srv := &server{hncDir: dir}
	sc := srv.v6State().scalpel

	var ctAttempts []ScalpelTuple
	sc.ctDelRunner = func(tp ScalpelTuple, seq uint32) error {
		ctAttempts = append(ctAttempts, tp)
		// 模拟正向五元组 ENOENT，验证反向五元组自动二次补刀
		if len(ctAttempts) == 1 {
			return parseNetlinkAck(buildTestNetlinkAckFrame(seq, 2))
		}
		return nil
	}
	sc.iptRunner = func(family int, payload string) error { return nil }

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v6/scalpel/cut", srv.apiScalpelCut)

	// 2a) Cloudflare 共享 CDN IP (104.16.132.229) 请求 cut_freeze_15m -> 409 拒绝并返回中文原因
	recCDN := httptest.NewRecorder()
	reqCDN := httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(
		`{"mode":"cut_freeze_15m","proto":"tcp","src_ip":"192.168.43.88","sport":54321,"dst_ip":"104.16.132.229","dport":443}`))
	mux.ServeHTTP(recCDN, reqCDN)
	if recCDN.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when freezing shared CDN IP, got %d: %s", recCDN.Code, recCDN.Body.String())
	}
	var cdnResp map[string]any
	_ = json.Unmarshal(recCDN.Body.Bytes(), &cdnResp)
	if cdnResp["guard_blocked"] != true || cdnResp["allowed_mode"] != "cut_once" || !strings.Contains(fmt.Sprint(cdnResp["detail"]), "共享") {
		t.Fatalf("unexpected CDN guard payload: %+v", cdnResp)
	}

	// 2b) 核心端口 53/853/123 请求 cut_freeze_15m -> 409 拒绝
	for _, port := range []int{53, 853, 123} {
		recPort := httptest.NewRecorder()
		reqPort := httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(
			fmt.Sprintf(`{"mode":"cut_freeze_15m","proto":"udp","src_ip":"192.168.43.88","sport":55100,"dst_ip":"198.51.100.77","dport":%d}`, port)))
		mux.ServeHTTP(recPort, reqPort)
		if recPort.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict for core port %d, got %d", port, recPort.Code)
		}
	}

	// 2c) 同一 Cloudflare 共享 CDN IP 使用 cut_once -> 200 放行 + 触发 ENOENT 反向元组二次补刀
	origResolve := scalpelResolveBinFn
	origExec := scalpelIptExecFn
	t.Cleanup(func() {
		scalpelResolveBinFn = origResolve
		scalpelIptExecFn = origExec
	})
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }
	hookPresent := false
	insertCount := 0
	scalpelIptExecFn = func(_ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if strings.Contains(line, "-C FORWARD -j HNC_SCALPEL") {
			if !hookPresent {
				return "No chain/target/match", errors.New("exit 1")
			}
			return "", nil
		}
		if strings.Contains(line, "-I FORWARD 1 -j HNC_SCALPEL") {
			hookPresent = true
			insertCount++
		}
		return "", nil
	}

	recOnce := httptest.NewRecorder()
	reqOnce := httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(
		`{"mode":"cut_once","proto":"tcp","src_ip":"192.168.43.88","sport":54321,"dst_ip":"104.16.132.229","dport":443,"mac":"aa:bb:cc:dd:ee:88"}`))
	mux.ServeHTTP(recOnce, reqOnce)
	if recOnce.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cut_once on shared CDN IP, got %d: %s", recOnce.Code, recOnce.Body.String())
	}
	if len(ctAttempts) != 2 || ctAttempts[1].SrcIP != "104.16.132.229" || ctAttempts[1].DstIP != "192.168.43.88" {
		t.Fatalf("expected forward ENOENT to retry reverse tuple, got attempts=%+v", ctAttempts)
	}
	if insertCount != 1 {
		t.Fatalf("expected initial FORWARD jump insert count=1, got %d", insertCount)
	}

	// 3. 模拟 netd 冲刷抹掉 FORWARD 跳转，验证非粘滞实时补挂 + UDP 1s 短暂拦截
	hookPresent = false
	udpResp, err := sc.Cut(time.Now(), ScalpelTuple{
		Proto: "udp", SrcIP: "192.168.43.88", Sport: 55001, DstIP: "198.51.100.88", Dport: 3478,
	}, "cut_once")
	if err != nil {
		t.Fatalf("UDP cut_once failed: %v", err)
	}
	if insertCount != 2 || !hookPresent {
		t.Fatalf("expected non-sticky ensureForwardJump to re-insert after netd flush, insertCount=%d", insertCount)
	}
	if udpResp["reset_cleanup_in_sec"].(int) != 1 {
		t.Fatalf("expected UDP transient reset TTL of 1s, got %v", udpResp["reset_cleanup_in_sec"])
	}
	sc.stopStandaloneTimer()

	// 4. 重复斩流原地刷新去重 & 128 条活跃上限保护
	engCap := newFlowScalpelEngine(nil)
	engCap.ctDelRunner = nil
	engCap.iptRunner = nil
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		_, _ = engCap.CutWithMAC(t0.Add(time.Duration(i)*time.Second), ScalpelTuple{
			Proto: "tcp", SrcIP: "192.168.43.50", Sport: 40000, DstIP: "198.51.100.50", Dport: 8443,
		}, "cut_freeze_15m", "aa:bb:cc:11:22:33")
	}
	engCap.stopStandaloneTimer()
	if got := engCap.ActiveRuleCount(); got != 2 {
		t.Fatalf("expected deduplicated active rules count == 2 (1 r5s + 1 r15m), got %d", got)
	}
	for i := 0; i < 150; i++ {
		_, _ = engCap.Cut(t0, ScalpelTuple{
			Proto: "tcp", SrcIP: "192.168.43.50", Sport: 20000 + i, DstIP: "198.51.100.50", Dport: 9000,
		}, "cut_once")
	}
	engCap.stopStandaloneTimer()
	if got := engCap.ActiveRuleCount(); got != scalpelMaxActiveRules {
		t.Fatalf("expected active rules capped at %d, got %d", scalpelMaxActiveRules, got)
	}

	// 5. 单一 time.Timer 事件驱动到期 & 空表 / HotspotOff 0 次后台唤醒验证
	var (
		actMu  sync.Mutex
		curAct = Activity{Known: true, Level: lvlActive, HotspotActive: true, ClientsOnline: 1}
		actCh  = make(chan struct{})
		sweeps atomic.Int64
	)
	setAct := func(next Activity) {
		actMu.Lock()
		curAct = next
		old := actCh
		actCh = make(chan struct{})
		actMu.Unlock()
		close(old)
	}

	engLoop := newFlowScalpelEngine(nil)
	engLoop.ctDelRunner = nil
	engLoop.iptRunner = func(family int, payload string) error { return nil }
	engLoop.resetDuration = 45 * time.Millisecond
	engLoop.activityHook = func() (<-chan struct{}, Activity) {
		actMu.Lock()
		defer actMu.Unlock()
		return actCh, curAct
	}
	origSweep := engLoop.SweepExpired
	engLoop.sweepHook = func(now time.Time) {
		sweeps.Add(1)
		origSweep(now)
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		engLoop.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	time.Sleep(60 * time.Millisecond)
	if engLoop.IsTickerActive() || sweeps.Load() != 0 {
		t.Fatalf("expected 0 timer wakeups when rule list is empty, active=%v sweeps=%d", engLoop.IsTickerActive(), sweeps.Load())
	}

	// 添加一条 45ms 到期规则: 触发一次到期回收后再次静默停表 0 唤醒
	_, _ = engLoop.Cut(time.Now(), ScalpelTuple{
		Proto: "tcp", SrcIP: "192.168.43.9", Sport: 34567, DstIP: "198.51.100.9", Dport: 443,
	}, "cut_once")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if engLoop.ActiveRuleCount() == 0 && !engLoop.IsTickerActive() && sweeps.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if engLoop.ActiveRuleCount() != 0 || engLoop.IsTickerActive() {
		t.Fatalf("expected rule auto-expired via single timer and returned to idle, rules=%d active=%v",
			engLoop.ActiveRuleCount(), engLoop.IsTickerActive())
	}

	// 再挂一条长生命周期规则后切入 HotspotOff: 立即清空规则并停表保持 0 唤醒
	engLoop.sweepHook = nil
	engLoop.resetDuration = 10 * time.Minute
	_, _ = engLoop.Cut(time.Now(), ScalpelTuple{
		Proto: "tcp", SrcIP: "192.168.43.9", Sport: 34568, DstIP: "198.51.100.9", Dport: 443,
	}, "cut_freeze_15m")
	setAct(Activity{Level: lvlHotspotOff, HotspotActive: false})
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if engLoop.ActiveRuleCount() == 0 && !engLoop.IsTickerActive() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if engLoop.ActiveRuleCount() != 0 || engLoop.IsTickerActive() {
		t.Fatalf("expected HotspotOff to flush active rules and stop timer (0 wakeups), rules=%d active=%v",
			engLoop.ActiveRuleCount(), engLoop.IsTickerActive())
	}
}
