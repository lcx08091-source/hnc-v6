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
