package main

import "testing"

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
