package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTelephonyRegistryDump5GSAAndNSA(t *testing.T) {
	sample := `
mActiveDataSubId=2
  Phone Id=0
    mSubId=1
    mServiceState={mOperatorAlphaLong=China Unicom, mOperatorAlphaShort=UNICOM, accessNetworkTechnology=LTE, isEnDcAvailable = false}
    mSignalStrength={mLte=CellSignalStrengthLte: rssi=-65 rsrp=-82 rsrq=-8 rssnr=20 cqiTableIndex=2147483647, mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = 2147483647 ssRsrq = 2147483647 ssSinr = 2147483647 }}
    mPreciseDataConnectionStates={InterfaceName: rmnet_data0}
  Phone Id=1
    mSubId=2
    mServiceState={mOperatorAlphaLong=China Mobile, mOperatorAlphaShort=CMCC, nrState=****, accessNetworkTechnology=LTE, isEnDcAvailable = true}
    mTelephonyDisplayInfo={network=LTE, overrideNetwork=NR_NSA}
    mSignalStrength={mLte=CellSignalStrengthLte: rssi=-59 rsrp=-85 rsrq=-7 rssnr=22, mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -112 ssRsrq = -14 ssSinr = 1 level = 1 }, primary=CellSignalStrengthLte}
    mPhysicalChannelConfigList=[{mConnectionStatus=PrimaryServing,mNetworkType=NR,mBand=78,mCellBandwidthDownlinkKhz=100000}]
    mPreciseDataConnectionStates={InterfaceName: rmnet_data2}
local logs:
  should_not_be_parsed
`
	st := parseTelephonyRegistryDump(sample, "rmnet_data2", 1763460000)
	if !st.Available {
		t.Fatalf("expected Available=true")
	}
	if st.Slot != 2 || st.SubID != 2 {
		t.Fatalf("expected slot=2 subId=2, got slot=%d subId=%d", st.Slot, st.SubID)
	}
	if st.RAT != "5G NSA" {
		t.Fatalf("expected RAT=5G NSA, got %q", st.RAT)
	}
	// Must prioritize weak NR (-112 dBm) over fake strong LTE anchor (-85 dBm)
	if st.RSRPdBm != -112 || st.LTERSRPdBm != -85 {
		t.Fatalf("expected NR RSRP=-112 and LTE anchor=-85, got rsrp=%d lte=%d", st.RSRPdBm, st.LTERSRPdBm)
	}
	if st.Band != "n78" || st.BandwidthMHz != 100 {
		t.Fatalf("expected n78 100MHz, got band=%q bw=%d", st.Band, st.BandwidthMHz)
	}
	if st.Quality != "weak" || st.RFCeilingFactor >= 0.80 {
		t.Fatalf("expected weak signal & reduced rf_ceiling_factor, got quality=%s factor=%v", st.Quality, st.RFCeilingFactor)
	}
}

func TestParseTelephonyRegistry5GA2CCAndCMCCBroadnetMOCN(t *testing.T) {
	// ColorOS 16 / Android 16 SA + NR_ADVANCED (5G-A) with mBand=0 hidden on PrimaryServing (resolved via NR-ARFCN 504990 -> n41) + SecondaryServing n28 (30MHz)
	sample := `
mActiveDataSubId = 1
  Phone Id = 0
    mSubId = 1
    mServiceState={mOperatorAlphaLong = 中国移动 5GA, mOperatorAlphaShort = CMCC, mOperatorNumeric = 46000, accessNetworkTechnology = NR, isEnDcAvailable = false}
    mTelephonyDisplayInfo={network = NR, overrideNetworkType = NR_ADVANCED}
    mSignalStrength={mNr=CellSignalStrengthNr:{ csiRsrp = -83 ssRsrp = -82 ssRsrq = -8 ssSinr = 22 level = 4 }}
    mPhysicalChannelConfigList=[{mConnectionStatus = PrimaryServing, mNetworkType = NR, mBand = 0, mDownlinkChannelNumber = 504990, mCellBandwidthDownlinkKhz = 100000}, {mConnectionStatus = SecondaryServing, mNetworkType = NR, mBand = 28, mDownlinkChannelNumber = 154570, mCellBandwidthDownlinkKhz = 30000}]
    mPreciseDataConnectionStates={InterfaceName: rmnet_data4}
`
	st := parseTelephonyRegistryDump(sample, "rmnet_data4", 1763460100)
	if !st.Available {
		t.Fatalf("expected Available=true")
	}
	if st.RAT != "5G SA" {
		t.Fatalf("SA NR_ADVANCED must keep RAT='5G SA' (never misflag as 5G NSA), got %q", st.RAT)
	}
	if !st.Is5GA || st.DisplayRAT != "5G-A" {
		t.Fatalf("expected Is5GA=true DisplayRAT='5G-A', got is5ga=%v display=%q", st.Is5GA, st.DisplayRAT)
	}
	if st.Carrier != "中国移动" || st.CarrierShort != "移动" {
		t.Fatalf("expected 中国移动 / 移动, got %q / %q", st.Carrier, st.CarrierShort)
	}
	if st.Band != "n41" || st.BandCombo != "n41+n28" || st.TotalBWMHz != 130 || st.CACount != 2 {
		t.Fatalf("expected n41 / n41+n28 / 130MHz / 2CC, got band=%q combo=%q totalBW=%d ca=%d", st.Band, st.BandCombo, st.TotalBWMHz, st.CACount)
	}
	if st.SharingMode == "" {
		t.Fatalf("expected MOCN sharing hint for CMCC n41+n28")
	}
	if st.Quality != "excellent" || st.QualityCN != "5G-A 极佳" {
		t.Fatalf("expected excellent / 5G-A 极佳, got %q / %q", st.Quality, st.QualityCN)
	}
}

func TestNRAndLTEARFCNFallbackAndRSRQCongestion(t *testing.T) {
	// China Broadnet (46015) sharing CMCC n41 via CellIdentityNr mNrArfcn fallback + heavy cell congestion (ssRsrq = -18)
	sampleCBN := `
mActiveDataSubId=1
  Phone Id=0
    mSubId=1
    mServiceState={mOperatorAlphaLong=CBN, mOperatorAlphaShort=CBN, mMcc=460, mMnc=15, accessNetworkTechnology=NR}
    CellIdentityNr:{ mPci = 210 mTac = 12345 mNrArfcn = 513000 mBands = [] }
    mSignalStrength={mNr=CellSignalStrengthNr:{ ssRsrp = -84 ssRsrq = -18 ssSinr = 16 }}
    mPreciseDataConnectionStates={InterfaceName: rmnet_data1}
`
	st := parseTelephonyRegistryDump(sampleCBN, "rmnet_data1", 1763460200)
	if !st.Available || st.Carrier != "中国广电" || st.Band != "n41" {
		t.Fatalf("expected 中国广电 on n41 via ARFCN fallback, got avail=%v carrier=%q band=%q", st.Available, st.Carrier, st.Band)
	}
	if st.Quality != "good" || st.RFCeilingFactor > 0.92 {
		t.Fatalf("expected RSRQ=-18 congestion downgrade from excellent to good (alpha<=0.92), got quality=%q alpha=%v", st.Quality, st.RFCeilingFactor)
	}
	if st.RSRQLabel != "基站拥塞" {
		t.Fatalf("expected RSRQLabel='基站拥塞', got %q", st.RSRQLabel)
	}

	// LTE EARFCN 1650 -> B3 (1800MHz) for China Telecom (46011) + Autorate ratGeneration check
	if b, freq := lteBandFromEARFCN(1650); b != "B3" || freq != 1800 {
		t.Fatalf("expected EARFCN 1650 -> B3 1800MHz, got %q %d", b, freq)
	}
	if ratGeneration("5G SA") != ratGeneration("5G NSA") || ratGeneration("5G-A") != "5G" {
		t.Fatalf("ratGeneration must group 5G SA/NSA/5G-A into '5G' so CA transitions do not wipe BaseRTT")
	}
	if ratGeneration("5G SA") == ratGeneration("4G LTE") {
		t.Fatalf("ratGeneration must distinguish 5G vs 4G LTE")
	}
}

func TestParseTelephonyRegistryPCILTERssiAndNSACarriers(t *testing.T) {
	sample := `
mActiveDataSubId=1
  Phone Id=0
    mSubId=1
    mServiceState={mOperatorAlphaLong=China Telecom, mOperatorAlphaShort=CTCC, mOperatorNumeric=46011, accessNetworkTechnology=LTE, isEnDcAvailable=true}
    mTelephonyDisplayInfo={network=LTE, overrideNetwork=NR_NSA}
    CellIdentityLte:{ mPci = 503 mEarfcn = 1850 mBandwidth = 20000 }
    CellIdentityNr:{ mPci = 1007 mNrArfcn = 633984 mBands = [78] }
    mCellInfo=[CellInfoNr:{mRegistered=NO mTimeStamp=123 CellIdentityNr:{ mPci = 888 mNrArfcn = 633984 }}]
    mSignalStrength={mLte=CellSignalStrengthLte: rssi=-61 rsrp=-86 rsrq=-9 rssnr=18, mNr=CellSignalStrengthNr:{ csiRsrp = -88 ssRsrp = -87 ssRsrq = -10 ssSinr = 15 level = 4 }}
    mPhysicalChannelConfigList=[{mConnectionStatus=PrimaryServing,mNetworkType=LTE,mBand=3,mDownlinkChannelNumber=1850,mCellBandwidthDownlinkKhz=20000,mPhysicalCellId=503},{mConnectionStatus=SecondaryServing,mNetworkType=NR,mBand=78,mDownlinkChannelNumber=633984,mCellBandwidthDownlinkKhz=100000,mPhysicalCellId=0}]
    mPreciseDataConnectionStates={InterfaceName: rmnet_data0}
`
	st := parseTelephonyRegistryDump(sample, "rmnet_data0", 1763460500)
	if !st.Available || st.RAT != "5G NSA" {
		t.Fatalf("expected 5G NSA Available=true, got avail=%v rat=%q", st.Available, st.RAT)
	}
	// NR PCI=0 is a valid 3GPP PCI (must set HasPCI=true and not be overwritten by unregistered mCellInfo mPci=888)
	if !st.HasPCI || st.PCI != 0 {
		t.Fatalf("expected NR PCI=0 HasPCI=true, got pci=%d hasPCI=%v", st.PCI, st.HasPCI)
	}
	if !st.HasLTEPCI || st.LTEPCI != 503 {
		t.Fatalf("expected LTE anchor PCI=503 HasLTEPCI=true, got ltePCI=%d has=%v", st.LTEPCI, st.HasLTEPCI)
	}
	if st.RSSIdBm != -61 || st.LTERSRPdBm != -86 || st.LTERSRQdB != -9 || st.LTESINRdB != 18 || !st.HasLTESINR {
		t.Fatalf("unexpected LTE anchor metrics: rssi=%d rsrp=%d rsrq=%d sinr=%d hasSinr=%v",
			st.RSSIdBm, st.LTERSRPdBm, st.LTERSRQdB, st.LTESINRdB, st.HasLTESINR)
	}
	if !st.HasSINR || !st.HasRSRQ || st.SINRdB != 15 || st.RSRQdB != -10 {
		t.Fatalf("expected NR HasSINR/HasRSRQ true with 15/-10, got sinr=%d(%v) rsrq=%d(%v)",
			st.SINRdB, st.HasSINR, st.RSRQdB, st.HasRSRQ)
	}
	if len(st.Carriers) != 2 {
		t.Fatalf("expected 2 carriers in NSA B3+n78, got %d", len(st.Carriers))
	}
	if st.Carriers[0].NetType != "LTE" || st.Carriers[0].PCI != 503 || !st.Carriers[0].HasPCI {
		t.Fatalf("unexpected carrier[0]: %+v", st.Carriers[0])
	}
	if st.Carriers[1].NetType != "NR" || st.Carriers[1].PCI != 0 || !st.Carriers[1].HasPCI || st.Carriers[1].BWMHz != 100 {
		t.Fatalf("unexpected carrier[1]: %+v", st.Carriers[1])
	}
}

func TestSignalRingHistoryHandoverAndModeSwitchReset(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	mon := newSignalMonitor(dir)

	var curSample hostSignalStatus
	mon.sampleFn = func(_ *server) hostSignalStatus {
		return curSample
	}

	baseTs := int64(1800000000)
	// 1. 写入 65 个蜂窝采样点, 验证 60 点环形缓冲滚动淘汰与 Min/Max/Avg/Jitter 计算
	for i := 0; i < 65; i++ {
		rsrp := -80 - (i % 10) // -80 .. -89 -> Min=-89, Max=-80, Jitter=9
		curSample = hostSignalStatus{
			Available:       true,
			Mode:            "cellular",
			RAT:             "5G SA",
			Band:            "n78",
			PCI:             100,
			HasPCI:          true,
			RSRPdBm:         rsrp,
			RSRQdB:          -9,
			HasRSRQ:         true,
			SINRdB:          18,
			HasSINR:         true,
			Bars:            4,
			Quality:         "excellent",
			QualityCN:       "5G 极佳",
			RFCeilingFactor: 1.0,
			UpdatedAt:       baseTs + int64(i*2),
		}
		_ = mon.Refresh(s)
	}

	got := mon.Get(s)
	if len(got.History) != 60 {
		t.Fatalf("expected ring buffer capped at 60 points, got %d", len(got.History))
	}
	if got.History[0].Ts != baseTs+10 || got.History[59].Ts != baseTs+128 {
		t.Fatalf("expected oldest Ts=%d newest Ts=%d, got %d .. %d",
			baseTs+10, baseTs+128, got.History[0].Ts, got.History[59].Ts)
	}
	if got.MinDbm != -89 || got.MaxDbm != -80 || got.JitterdB != 9 {
		t.Fatalf("expected min=-89 max=-80 jitter=9, got min=%d max=%d jitter=%d",
			got.MinDbm, got.MaxDbm, got.JitterdB)
	}
	if got.HandoverCount != 0 {
		t.Fatalf("expected HandoverCount=0 before cell switch, got %d", got.HandoverCount)
	}

	// Copy-on-Write 验证: 篡改返回快照切片元素不得污染缓存
	got.History[0].RSRPdBm = -140
	got.InterferenceSources[0].Pct = 99
	gotAgain := mon.PeekCached(s)
	if gotAgain.History[0].RSRPdBm == -140 || gotAgain.InterferenceSources[0].Pct == 99 {
		t.Fatalf("copy-on-write violated: mutating returned slices corrupted cached state")
	}

	// 2. 模拟近 5 分钟内发生 3 次 PCI / 频段乒乓切换 -> HandoverCount=3 且优先判 rf_interference
	switches := []struct {
		dt   int64
		pci  int
		band string
	}{
		{135, 205, "n78"},
		{150, 205, "n28"},
		{170, 100, "n78"},
	}
	var stHO hostSignalStatus
	for _, sw := range switches {
		curSample.PCI = sw.pci
		curSample.Band = sw.band
		curSample.UpdatedAt = baseTs + sw.dt
		stHO = mon.Refresh(s)
	}
	if stHO.HandoverCount != 3 {
		t.Fatalf("expected HandoverCount=3 after 3 ping-pong switches within 300s, got %d", stHO.HandoverCount)
	}
	if stHO.Diagnosis != "rf_interference" || stHO.InterferenceLevel != "severe" {
		t.Fatalf("expected Diagnosis='rf_interference' and severe interference on 3 handovers, got diag=%q level=%q",
			stHO.Diagnosis, stHO.InterferenceLevel)
	}

	// 推进超过 300s 滑窗且不再切换 -> 旧切换记录全部过期归零
	curSample.UpdatedAt = baseTs + 500
	stExpired := mon.Refresh(s)
	if stExpired.HandoverCount != 0 {
		t.Fatalf("expected HandoverCount=0 after >300s window expiry, got %d", stExpired.HandoverCount)
	}

	// 3. 切换至 Wi-Fi STA 模式 -> 蜂窝环形历史与切换记录必须立即清空重置
	curSample = hostSignalStatus{
		Available:       true,
		Mode:            "wifi_sta",
		RAT:             "Wi-Fi 中继",
		Band:            "5GHz",
		WifiRSSIdBm:     -55,
		WifiNoiseDbm:    -92,
		SINRdB:          37,
		HasSINR:         true,
		Bars:            4,
		Quality:         "excellent",
		QualityCN:       "Wi-Fi 极佳",
		RFCeilingFactor: 1.0,
		UpdatedAt:       baseTs + 510,
	}
	stWifi := mon.Refresh(s)
	if len(stWifi.History) != 1 || stWifi.History[0].WifiRSSIdBm != -55 || stWifi.History[0].RSRPdBm != 0 {
		t.Fatalf("expected history reset to 1 wifi_sta point on mode switch, got len=%d pt=%+v",
			len(stWifi.History), stWifi.History)
	}

	// 4. 验证 TriggerRefresh(s, true) 1500ms lastForceAt 防抖保护
	var asyncCnt atomic.Int32
	mon.sampleFn = func(_ *server) hostSignalStatus {
		asyncCnt.Add(1)
		return curSample
	}
	mon.TriggerRefresh(s, true)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && asyncCnt.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	for mon.inFlight.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	beforeCoalesced := mon.asyncCoalesced.Load()
	// 立即再次 force 刷新(间隔 < 1500ms), 必须被防抖拦截且不再触发 sampleFn
	mon.TriggerRefresh(s, true)
	time.Sleep(30 * time.Millisecond)
	if asyncCnt.Load() != 1 || mon.asyncCoalesced.Load() <= beforeCoalesced {
		t.Fatalf("expected rapid force refresh (<1500ms) debounced, asyncCnt=%d coalesced=%d->%d",
			asyncCnt.Load(), beforeCoalesced, mon.asyncCoalesced.Load())
	}
}

func TestSignalInterference4DBug1FixSINR6dBAnd1dB(t *testing.T) {
	s, _, _ := newV6TestMux(t)

	// 场景 A (真机截图 Bug 1): RSRP=-86 良好, SINR=6dB (轻度干扰) -> 绝不能谎称 "ok"/"信号纯净"!
	stMild := hostSignalStatus{
		Available:       true,
		Mode:            "cellular",
		RAT:             "5G SA",
		Band:            "n41",
		RSRPdBm:         -86,
		RSRQdB:          -9,
		HasRSRQ:         true,
		SINRdB:          6,
		HasSINR:         true,
		Bars:            3,
		Quality:         "good",
		QualityCN:       "5G 良好",
		RFCeilingFactor: 0.95,
	}
	enrichSignalDiagnosis(&stMild, s)
	if stMild.Diagnosis != "rf_interference" {
		t.Fatalf("expected Diagnosis='rf_interference' for SINR=6dB, got %q (%s)", stMild.Diagnosis, stMild.DiagnosisCN)
	}
	if strings.Contains(stMild.DiagnosisCN, "信号纯净") {
		t.Fatalf("SINR=6dB must NEVER claim clean signal, got %q", stMild.DiagnosisCN)
	}
	if stMild.InterferenceLevel != "mild" || stMild.InterferencePct < 25 || stMild.InterferencePct > 49 {
		t.Fatalf("expected mild interference (25..49%%) for SINR=6dB, got level=%q pct=%d label=%q",
			stMild.InterferenceLevel, stMild.InterferencePct, stMild.InterferenceLabel)
	}
	wantIDs := []string{"co_channel", "cell_load", "multipath_fading", "bufferbloat"}
	if len(stMild.InterferenceSources) != 4 {
		t.Fatalf("expected 4 interference sources, got %d", len(stMild.InterferenceSources))
	}
	for i, id := range wantIDs {
		if stMild.InterferenceSources[i].ID != id {
			t.Fatalf("source[%d] expected id=%q, got %q", i, id, stMild.InterferenceSources[i].ID)
		}
	}

	// 场景 B: RSRP=-86 格数充足, 但 SINR=1dB (<3dB 强同频干扰) -> severe (75..100%%) 且优先判 rf_interference
	stSevere := stMild
	stSevere.SINRdB = 1
	stSevere.Quality = "fair"
	// 即使同时叠加上游轻度排队膨胀, SINR<3 仍优先归因 rf_interference
	s.autorate.mu.Lock()
	s.autorate.st.Enabled = true
	s.autorate.st.RTTMs = 68
	s.autorate.st.DeltaRTTMs = 35
	s.autorate.st.RTTDeltaMs = 25
	s.autorate.mu.Unlock()
	enrichSignalDiagnosis(&stSevere, s)
	if stSevere.Diagnosis != "rf_interference" {
		t.Fatalf("expected SINR=1dB (<3dB) to prioritize Diagnosis='rf_interference', got %q (%s)",
			stSevere.Diagnosis, stSevere.DiagnosisCN)
	}
	if stSevere.InterferenceLevel != "severe" || stSevere.InterferencePct < 75 {
		t.Fatalf("expected severe interference (>=75%%) for SINR=1dB, got level=%q pct=%d",
			stSevere.InterferenceLevel, stSevere.InterferencePct)
	}

	// 恢复 autorate 空闲态, 验证单测零值守卫 effectiveSINR:
	// 未设 HasSINR 且 SINRdB==0 的旧测试字面量不得误判为 0dB 干扰; 显式 HasSINR==true 且 SINRdB==0 则判为真实 0dB 强干扰!
	s.autorate.mu.Lock()
	s.autorate.st = autorateStatus{}
	s.autorate.mu.Unlock()

	stZeroOmitted := hostSignalStatus{
		Available:       true,
		Mode:            "cellular",
		RAT:             "5G SA",
		RSRPdBm:         -85,
		Quality:         "excellent",
		RFCeilingFactor: 1.0,
	}
	enrichSignalDiagnosis(&stZeroOmitted, s)
	if stZeroOmitted.Diagnosis != "ok" {
		t.Fatalf("omitted SINRdB=0 (HasSINR=false) must stay 'ok' for legacy tests, got %q", stZeroOmitted.Diagnosis)
	}

	stRealZero := stZeroOmitted
	stRealZero.HasSINR = true
	stRealZero.Quality = "fair"
	enrichSignalDiagnosis(&stRealZero, s)
	if stRealZero.Diagnosis != "rf_interference" {
		t.Fatalf("explicit SINRdB=0 with HasSINR=true must trigger 'rf_interference', got %q", stRealZero.Diagnosis)
	}

	// 验证模拟快照 simSignalSnapshot 补齐双载波、多点历史与四维干扰源
	sim := simSignalSnapshot(s)
	if len(sim.Carriers) < 2 || len(sim.History) < 10 || len(sim.InterferenceSources) != 4 || !sim.HasSINR {
		t.Fatalf("simSignalSnapshot incomplete: carriers=%d history=%d sources=%d hasSINR=%v",
			len(sim.Carriers), len(sim.History), len(sim.InterferenceSources), sim.HasSINR)
	}
}

func TestSignalWifiSTANeverFallsBackToCellular(t *testing.T) {
	// 1. 验证 isWifiSTAUpstream 识别 wlan0 / wlan1 及 UpstreamClass=="wifi", 且排除本地 AP 接口与蜂窝网卡
	if !isWifiSTAUpstream(ifaceDetect{Iface: "wlan0", TetherUpstream: "wlan1"}, "wlan1") {
		t.Fatalf("expected wlan1 STA (with wlan0 AP) recognized as wifi_sta upstream")
	}
	if !isWifiSTAUpstream(ifaceDetect{Iface: "ap0", UpstreamClass: "wifi"}, "") {
		t.Fatalf("expected UpstreamClass='wifi' recognized as wifi_sta upstream")
	}
	if isWifiSTAUpstream(ifaceDetect{Iface: "wlan0"}, "wlan0") {
		t.Fatalf("hotspot AP iface itself must NOT be treated as wifi_sta upstream")
	}
	if isWifiSTAUpstream(ifaceDetect{Iface: "wlan0", UpstreamClass: "cellular"}, "rmnet_data1") {
		t.Fatalf("cellular rmnet_data1 must NOT be treated as wifi_sta upstream")
	}

	// 2. cmd wifi status 失败时兜底读取 /proc/net/wireless 提取 wlan1 RSSI 与 Noise
	procSample := `Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
 wlan0: 0000   70.  -42.  -95.        0      0      0      0      0        0
 wlan1: 0000   62.  -61.  -93.        0      0      0      3      0        0
`
	stFallback := sampleWifiSTASignal(
		"wlan1",
		"wlan0",
		1763460800,
		func() (string, error) { return "", errors.New("cmd wifi timeout") },
		func() (string, error) { return procSample, nil },
	)
	if !stFallback.Available || stFallback.Mode != "wifi_sta" || stFallback.UpstreamIface != "wlan1" {
		t.Fatalf("expected /proc/net/wireless fallback on wlan1, got %+v", stFallback)
	}
	if stFallback.WifiRSSIdBm != -61 || stFallback.WifiNoiseDbm != -93 || stFallback.SINRdB != 32 || !stFallback.HasSINR {
		t.Fatalf("expected RSSI=-61 Noise=-93 SNR=32, got rssi=%d noise=%d sinr=%d(%v)",
			stFallback.WifiRSSIdBm, stFallback.WifiNoiseDbm, stFallback.SINRdB, stFallback.HasSINR)
	}

	// 3. cmd wifi status 与 /proc/net/wireless 全部失败 -> 必须返回 Mode="wifi_sta", Available=false, RFCeilingFactor=1.0, 绝不串台蜂窝!
	stFail := sampleWifiSTASignal(
		"wlan1",
		"wlan0",
		1763460900,
		func() (string, error) { return "", errors.New("cmd wifi denied") },
		func() (string, error) { return "Inter-|\n face |\n", nil },
	)
	if stFail.Available || stFail.Mode != "wifi_sta" || stFail.RFCeilingFactor != 1.0 {
		t.Fatalf("expected Mode='wifi_sta' Available=false RFCeilingFactor=1.0 on total failure, got %+v", stFail)
	}

	// 4. 集成验证 sampleHostSignal: 写入 run/iface_detect.json 指向不存在的虚构无线口 wlan9, 确认直接返回 wifi_sta 绝不调蜂窝基带
	s, _, dir := newV6TestMux(t)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"), []byte(`{
		"iface": "ap0",
		"tether_upstream": "wlan9",
		"upstream_class": "wifi"
	}`), 0o600)
	mon := newSignalMonitor(dir)
	stHost := mon.sampleHostSignal(s)
	if stHost.Mode != "wifi_sta" || stHost.Available || stHost.RFCeilingFactor != 1.0 {
		t.Fatalf("sampleHostSignal on broken wifi_sta wlan9 must return Mode='wifi_sta' Available=false alpha=1.0, got %+v", stHost)
	}
}

func TestSignalMissingSINRNeverDowngradesFullBarsAndJSONTags(t *testing.T) {
	// 基带仅上报 RSRP=-82, RSRQ=-8, 未上报 rssnr/ssSinr (2147483647 -> HasSINR=false, SINRdB=0)
	dumpNoSINR := `
mActiveDataSubId=1
  Phone Id=0
    mSubId=1
    mServiceState={mOperatorAlphaLong=China Mobile, mOperatorAlphaShort=CMCC, mOperatorNumeric=46000, accessNetworkTechnology=NR, isEnDcAvailable=false}
    mSignalStrength={mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -82 ssRsrq = -8 ssSinr = 2147483647 level = 4 }}
    mPhysicalChannelConfigList=[{mConnectionStatus=PrimaryServing,mNetworkType=NR,mBand=41,mCellBandwidthDownlinkKhz=100000}]
    mPreciseDataConnectionStates={InterfaceName: rmnet_data0}
`
	st := parseTelephonyRegistryDump(dumpNoSINR, "rmnet_data0", 1763560000)
	if !st.Available || st.HasSINR || st.SINRdB != 0 {
		t.Fatalf("expected Available=true HasSINR=false SINRdB=0, got avail=%v hasSINR=%v sinr=%d",
			st.Available, st.HasSINR, st.SINRdB)
	}
	if st.Bars != 4 || st.Quality != "excellent" || st.RFCeilingFactor != 1.0 {
		t.Fatalf("missing SINR must NEVER downgrade full RSRP=-82/RSRQ=-8 to 2 bars: got bars=%d quality=%q alpha=%v",
			st.Bars, st.Quality, st.RFCeilingFactor)
	}
	if st.SINRLabel == "干扰明显" || st.SINRLabel == "嘈杂易跳Ping" || st.SINRLabel != "基带未上报" {
		t.Fatalf("missing SINR must report '基带未上报' instead of interference label, got %q", st.SINRLabel)
	}

	// 验证真实 0 dB (ssSinr = 0, HasSINR = true) 与缺失 0 严格区分
	dumpRealZero := strings.Replace(dumpNoSINR, "ssSinr = 2147483647", "ssSinr = 0", 1)
	stZero := parseTelephonyRegistryDump(dumpRealZero, "rmnet_data0", 1763560010)
	if !stZero.HasSINR || stZero.SINRdB != 0 || stZero.Bars != 2 || stZero.SINRLabel != "干扰明显" {
		t.Fatalf("real 0 dB SINR must set HasSINR=true and downgrade to 2 bars / '干扰明显', got hasSINR=%v bars=%d label=%q",
			stZero.HasSINR, stZero.Bars, stZero.SINRLabel)
	}

	// 验证 SignalSnapshot 与 SignalHistoryPoint JSON 显式输出 has_sinr 与 sinr_db (无 omitempty 吞零值)
	s, _, dir := newV6TestMux(t)
	mon := newSignalMonitor(dir)
	mon.sampleFn = func(_ *server) SignalSnapshot { return st }
	refreshed := mon.Refresh(s)
	jb, err := json.Marshal(refreshed)
	if err != nil {
		t.Fatalf("marshal SignalSnapshot: %v", err)
	}
	rawJSON := string(jb)
	if !strings.Contains(rawJSON, `"has_sinr":false`) {
		t.Fatalf("expected explicit \"has_sinr\":false in JSON, got %s", rawJSON)
	}
	if !strings.Contains(rawJSON, `"sinr_db":0`) {
		t.Fatalf("expected explicit \"sinr_db\":0 in SignalHistoryPoint JSON, got %s", rawJSON)
	}
}

func TestSignalInterferenceSourcesZeroFakePercentages(t *testing.T) {
	// 1. 蜂窝未上报 SINR / RSRQ 且 Autorate 未开启 -> 对应干扰源必须返回 Available=false, Pct=0 与明确 reason_code
	stCell := hostSignalStatus{
		Available:       true,
		Mode:            "cellular",
		RAT:             "4G LTE",
		RSRPdBm:         -85,
		HasSINR:         false,
		HasRSRQ:         false,
		Bars:            4,
		Quality:         "excellent",
		RFCeilingFactor: 1.0,
	}
	computeInterference4D(&stCell, autorateStatus{Enabled: false})
	if len(stCell.InterferenceSources) != 4 {
		t.Fatalf("expected 4 sources, got %d", len(stCell.InterferenceSources))
	}
	byID := map[string]SignalInterferenceSource{}
	for _, src := range stCell.InterferenceSources {
		byID[src.ID] = src
	}
	if c := byID["co_channel"]; c.Available || c.Pct != 0 || c.ReasonCode != "metric_unavailable" {
		t.Fatalf("co_channel without SINR must be unavailable with pct=0, got %+v", c)
	}
	if l := byID["cell_load"]; l.Available || l.Pct != 0 || l.ReasonCode != "metric_unavailable" {
		t.Fatalf("cell_load without RSRQ must be unavailable with pct=0, got %+v", l)
	}
	if m := byID["multipath_fading"]; m.Available || m.Pct != 0 || m.ReasonCode != "metric_unavailable" {
		t.Fatalf("single-point multipath_fading without fading must be unavailable with pct=0, got %+v", m)
	}
	if b := byID["bufferbloat"]; b.Available || b.Pct != 0 || b.ReasonCode != "probe_disabled" {
		t.Fatalf("bufferbloat with disabled Autorate must be unavailable with probe_disabled, got %+v", b)
	}
	if stCell.InterferencePct != 0 || stCell.InterferenceLevel != "unavailable" {
		t.Fatalf("expected overall InterferencePct=0 Level='unavailable', got pct=%d level=%q",
			stCell.InterferencePct, stCell.InterferenceLevel)
	}

	// 2. Wi-Fi STA 未上报 Noise 与 Link speed -> 严禁伪造 56/28/10/12 等固定百分比
	stWifi := parseWifiStatusOutput("Wifi is connected\nRSSI: -74\nFrequency: 2437 MHz\n", "wlan1", 1763560100)
	if !stWifi.Available || stWifi.HasSINR {
		t.Fatalf("unexpected wifi status: %+v", stWifi)
	}
	wByID := map[string]SignalInterferenceSource{}
	for _, src := range stWifi.InterferenceSources {
		wByID[src.ID] = src
	}
	if wc := wByID["co_channel"]; wc.Available || wc.Pct != 0 || wc.ReasonCode != "metric_unavailable" {
		t.Fatalf("wifi co_channel without Noise must NOT fake 56/28%%, got %+v", wc)
	}
	if wl := wByID["cell_load"]; wl.Available || wl.Pct != 0 || wl.ReasonCode != "metric_unavailable" {
		t.Fatalf("wifi cell_load without Link speed must NOT fake 12%%, got %+v", wl)
	}
}

func TestRC7Signal5GSAKeyValuePlaceholderPCIIMSVoiceAndStaleHistory(t *testing.T) {
	// 1. B031: accessNetworkTechnology=NR 后紧跟空格分隔键值(如 nsac=0 / rejectCause=0) + getRilDataRadioTechnology=20(NR_SA)
	//    + 空占位 mPhysicalChannelConfigList PCI=0/Band=0/BW=0/ARFCN=0 跳过以保留 CellIdentityNr 真值 PCI=858
	//    + IMS 语音专网口(PcscfAddresses 非空 / [ims])剔除 + 缺 mSubId 时优选 mDataConnectionState=2 槽位
	//    + 单数 Local log: 截断
	dumpSA := `
mActiveDataSubId=2
  Phone Id=0
    mDataConnectionState=0
    mServiceState={mOperatorAlphaLong=China Unicom, mOperatorNumeric=46001, accessNetworkTechnology=LTE, getRilDataRadioTechnology=14(LTE)}
    mSignalStrength={mLte=CellSignalStrengthLte: rssi=-63 rsrp=-79 rsrq=-7 rssnr=24}
    LinkProperties: {InterfaceName: rmnet_data0 LinkAddresses: [ 2408:8000::2/64 ] PcscfAddresses: [ 2408:8000::1 ]}
  Phone Id=1
    mDataConnectionState=2
    mServiceState={mOperatorAlphaLong=China Mobile, mOperatorNumeric=46000, accessNetworkTechnology=NR nsac=0 rejectCause=0, getRilDataRadioTechnology=20(NR_SA), isEnDcAvailable=false}
    CellIdentityNr:{ mPci = 858 mTac = 20481 mNrArfcn = 504990 mBands = [41] }
    mSignalStrength={mNr=CellSignalStrengthNr:{ csiRsrp = -85 ssRsrp = -84 ssRsrq = -9 ssSinr = 19 level = 4 }}
    mPhysicalChannelConfigList=[{mConnectionStatus=PrimaryServing,mNetworkType=NR,mBand=0,mDownlinkChannelNumber=0,mCellBandwidthDownlinkKhz=0,mPhysicalCellId=0}]
    mPreciseDataConnectionStates={ApnSetting: [ims] LinkProperties: {InterfaceName: rmnet_data1 PcscfAddresses: [ 2409:8080::9 ]}, ApnSetting: [default,supl] LinkProperties: {InterfaceName: rmnet_data3 LinkAddresses: [ 10.66.77.88/24 ]}}
Local log:
  Phone Id=1 mDataConnectionState=2 ssRsrp=-135 accessNetworkTechnology=LTE
`
	if !puIsLocalLogsHeader("Local log:") || !puIsLocalLogsHeader("  local logs:") {
		t.Fatal("puIsLocalLogsHeader must recognize both singular 'Local log:' and plural 'local logs:'")
	}
	stSA := parseTelephonyRegistryDump(dumpSA, "", 1800100000)
	if !stSA.Available || stSA.Slot != 2 {
		t.Fatalf("expected active data Phone Id=1 (Slot=2 via mDataConnectionState=2), got avail=%v slot=%d", stSA.Available, stSA.Slot)
	}
	if stSA.RAT != "5G SA" {
		t.Fatalf("expected RAT='5G SA' (must not swallow 'nsac=0' as NSA), got %q", stSA.RAT)
	}
	if !stSA.HasPCI || stSA.PCI != 858 || stSA.Band != "n41" {
		t.Fatalf("empty placeholder PCI=0/Band=0/BW=0/ARFCN=0 must be skipped for CellIdentityNr PCI=858 n41, got pci=%d(%v) band=%q",
			stSA.PCI, stSA.HasPCI, stSA.Band)
	}
	if stSA.UpstreamIface != "rmnet_data3" {
		t.Fatalf("IMS Pcscf interface rmnet_data1 must be skipped in favor of default data rmnet_data3, got %q", stSA.UpstreamIface)
	}
	if stSA.RSRPdBm != -84 {
		t.Fatalf("singular 'Local log:' tail must be truncated before ssRsrp=-135, got rsrp=%d", stSA.RSRPdBm)
	}

	// 验证显式 accessNetworkTechnology=NR_NSA 准确识别为 5G NSA
	dumpExplicitNSA := strings.Replace(dumpSA, "accessNetworkTechnology=NR nsac=0 rejectCause=0, getRilDataRadioTechnology=20(NR_SA)", "accessNetworkTechnology=NR_NSA", 1)
	if stNSA := parseTelephonyRegistryDump(dumpExplicitNSA, "rmnet_data3", 1800100010); stNSA.RAT != "5G NSA" {
		t.Fatalf("expected explicit NR_NSA -> '5G NSA', got %q", stNSA.RAT)
	}

	// 2. B031: 环形历史剔除 Ts < UpdatedAt-600 的陈旧点(如息屏 27h 后唤醒), 且相邻间隔 >300s 的跨时段基站变更不计入乒乓切换
	s, _, dir := newV6TestMux(t)
	mon := newSignalMonitor(dir)
	var cur hostSignalStatus
	mon.sampleFn = func(_ *server) hostSignalStatus { return cur }

	t0 := int64(1800200000)
	cur = hostSignalStatus{
		Available: true, Mode: "cellular", RAT: "5G SA", Band: "n41",
		PCI: 101, HasPCI: true, RSRPdBm: -82, Bars: 4, Quality: "excellent", RFCeilingFactor: 1.0,
		UpdatedAt: t0,
	}
	_ = mon.Refresh(s)

	// 27 小时(97200s > 600s)后在新基站唤醒采样: 旧点必须被剔除, 且间隔 >300s 绝不计为近期基站切换
	cur.PCI = 309
	cur.Band = "n78"
	cur.RSRPdBm = -95
	cur.UpdatedAt = t0 + 97200
	afterSleep := mon.Refresh(s)
	if len(afterSleep.History) != 1 || afterSleep.History[0].Ts != t0+97200 {
		t.Fatalf("expected 27h stale sample evicted leaving 1 fresh point, got len=%d hist=%+v", len(afterSleep.History), afterSleep.History)
	}
	if afterSleep.HandoverCount != 0 {
		t.Fatalf("cell change across >300s sleep gap must NOT increment HandoverCount, got %d", afterSleep.HandoverCount)
	}
	if afterSleep.JitterdB != 0 {
		t.Fatalf("stale pre-sleep RSRP must not pollute current JitterdB, got %d", afterSleep.JitterdB)
	}
}

func TestSignalRealDeviceMAccessTechnologyZeroCellIdAndStaleGet(t *testing.T) {
	// 1. 真机 mAccessTechnology = NR (末尾带空格, 无 NSA 指示) + 尾随全零占位 CellIdentityNr / CellIdentityLte 不覆写有效 Fallback*
	dumpRealSA := `
mActiveDataSubId = 1
  Phone Id = 0
    mSubId = 1
    mDataConnectionState = 2
    mServiceState={mOperatorAlphaLong = China Mobile, mOperatorNumeric = 46000, mAccessTechnology = NR , isEnDcAvailable = false}
    CellIdentityNr:{ mPci = 412 mTac = 20481 mNrArfcn = 504990 mBands = [41] }
    CellIdentityNr:{ mPci = 0 mTac = 0 mNrArfcn = 0 mBands = [] }
    CellIdentityLte:{ mPci = 188 mEarfcn = 1650 mBands = [3] mBandwidth = 20000 }
    CellIdentityLte:{ mPci = 0 mEarfcn = 0 mBands = [] mBandwidth = 0 }
    mSignalStrength={mNr=CellSignalStrengthNr:{ csiRsrp = -81 ssRsrp = -80 ssRsrq = -8 ssSinr = 21 level = 4 }}
    mPreciseDataConnectionStates={InterfaceName: rmnet_data2}
`
	st1 := parseTelephonyRegistryDump(dumpRealSA, "rmnet_data2", 1800300000)
	if !st1.Available || st1.RAT != "5G SA" {
		t.Fatalf("expected real-device 'mAccessTechnology = NR ' -> RAT='5G SA', got avail=%v rat=%q", st1.Available, st1.RAT)
	}
	if !st1.HasPCI || st1.PCI != 412 || st1.Band != "n41" || st1.ARFCN != 504990 {
		t.Fatalf("all-zero CellIdentityNr placeholder must not overwrite FallbackNR*, got pci=%d(%v) band=%q arfcn=%d",
			st1.PCI, st1.HasPCI, st1.Band, st1.ARFCN)
	}

	// 2. 真机 mAccessTechnology = NR_SA + mRilDataRadioTechnology = 20(NR_SA) 及 LTE 全零占位不覆写 FallbackLTE*
	dumpSAExplicit := `
mActiveDataSubId = 1
  Phone Id = 0
    mSubId = 1
    mServiceState={mOperatorAlphaLong = China Telecom, mOperatorNumeric = 46011, mAccessTechnology = NR_SA, mRilDataRadioTechnology = 20(NR_SA)}
    CellIdentityNr:{ mPci = 616 mNrArfcn = 633984 mBands = [78] }
    mSignalStrength={mNr=CellSignalStrengthNr:{ ssRsrp = -85 ssRsrq = -9 ssSinr = 18 level = 4 }}
    mPreciseDataConnectionStates={InterfaceName: rmnet_data0}
`
	st2 := parseTelephonyRegistryDump(dumpSAExplicit, "rmnet_data0", 1800300010)
	if !st2.Available || st2.RAT != "5G SA" || st2.PCI != 616 || st2.Band != "n78" {
		t.Fatalf("expected 'mAccessTechnology = NR_SA' + mRilDataRadioTechnology -> '5G SA' PCI=616 n78, got rat=%q pci=%d band=%q",
			st2.RAT, st2.PCI, st2.Band)
	}

	dumpLTEZero := `
mActiveDataSubId = 1
  Phone Id = 0
    mSubId = 1
    mServiceState={mOperatorAlphaLong = China Unicom, mOperatorNumeric = 46001, mAccessTechnology = LTE }
    CellIdentityLte:{ mPci = 222 mEarfcn = 1650 mBands = [3] mBandwidth = 20000 }
    CellIdentityLte:{ mPci = 0 mEarfcn = 0 mBands = [] mBandwidth = 0 }
    mSignalStrength={mLte=CellSignalStrengthLte: rssi=-62 rsrp=-83 rsrq=-8 rssnr=19}
    mPreciseDataConnectionStates={InterfaceName: rmnet_data0}
`
	stLTE := parseTelephonyRegistryDump(dumpLTEZero, "rmnet_data0", 1800300020)
	if !stLTE.Available || stLTE.RAT != "4G LTE" || !stLTE.HasPCI || stLTE.PCI != 222 || stLTE.Band != "B3" || stLTE.BandwidthMHz != 20 {
		t.Fatalf("all-zero CellIdentityLte placeholder must not overwrite FallbackLTE*, got rat=%q pci=%d(%v) band=%q bw=%d",
			stLTE.RAT, stLTE.PCI, stLTE.HasPCI, stLTE.Band, stLTE.BandwidthMHz)
	}

	// 3. Get() 当 now - cp.UpdatedAt > 600 时归零过期快照的 HandoverCount 与 JitterdB
	s, _, dir := newV6TestMux(t)
	mon := newSignalMonitor(dir)
	mon.mu.Lock()
	mon.last = hostSignalStatus{
		Available:       true,
		Mode:            "cellular",
		RAT:             "5G SA",
		Band:            "n41",
		RSRPdBm:         -85,
		SINRdB:          18,
		HasSINR:         true,
		Bars:            4,
		Quality:         "excellent",
		RFCeilingFactor: 1.0,
		HandoverCount:   4,
		JitterdB:        11,
		UpdatedAt:       time.Now().Unix() - 605,
	}
	mon.lastAt = time.Now() // 避免异步触发采样干扰断言
	mon.mu.Unlock()

	gotStale := mon.Get(s)
	if gotStale.HandoverCount != 0 || gotStale.JitterdB != 0 {
		t.Fatalf("expected Get() to zero HandoverCount and JitterdB when UpdatedAt >600s old, got ho=%d jitter=%d",
			gotStale.HandoverCount, gotStale.JitterdB)
	}
}


