// Package output - microburst.go: v5.34 Sub-Second Human Touch Causality,
// OS Uplink DSCP Classification & ECH Pre-Binding Ring.
package output

import (
	"hash/fnv"
	"math"
	"math/bits"
	"strings"
)

const (
	DSCPNone        uint8 = 0
	DSCPLow         uint8 = 1 // LE(1), CS1(8) — Apple NET_SERVICE_TYPE_BK / Scavenger
	DSCPInteractive uint8 = 2 // AF21(18), AF22(20), AF31(26), AF32(28)
	DSCPRealtime    uint8 = 3 // CS3(24), CS4(32), AF4x(34..38), CS5(40), VA(44), NQB(45), EF(46)
)

// ClassifyUplinkDSCP folds 6-bit uplink DSCP into 4 physical tiers, stripping CS6(48)/CS7(56) per RFC 8325 §8.2.
func ClassifyUplinkDSCP(dscp uint8) uint8 {
	switch dscp {
	case 1, 8:
		return DSCPLow
	case 18, 20, 26, 28:
		return DSCPInteractive
	case 24, 32, 34, 36, 38, 40, 44, 45, 46:
		return DSCPRealtime
	default:
		return DSCPNone
	}
}

// IsPushChannelPort identifies Apple APNs (5223), Google FCM (5228-5230), and Xiaomi/OEM Push (5222).
func IsPushChannelPort(port uint16) bool {
	switch port {
	case 5222, 5223, 5228, 5229, 5230:
		return true
	default:
		return false
	}
}

const (
	mbStateIdle       uint8 = 0
	mbStateUlArmed    uint8 = 1
	mbStateDlBurst    uint8 = 2
	mbStateUnprovoked uint8 = 3

	mbFlagPendingD2C uint8 = 1 << 0

	mbQuietGapMs      int64 = 250
	mbCausalRTTMaxMs  int64 = 350
	mbMaxBurstDurMs   int64 = 2500
	mbRefractoryDNSMs int64 = 250
	mbSessionResetMs  int64 = 90000
	mbImpulseHalfLife       = 15.0
)

// PendingDNSSlot tracks recent DNS Response -> Connect (<150ms) causality & ECH QNAME recovery (256-slot ring).
type PendingDNSSlot struct {
	RespMonoMs int64
	KeyHash    uint64
	QName      string
	Consumed   bool
}

// PendingDNSRing is an O(1) fixed-size 256-slot open-addressed table protected by Writer.mu.
type PendingDNSRing struct {
	slots [256]PendingDNSSlot
}

func dnsPairHash(mac, ip string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(mac)))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(ip))
	return h.Sum64()
}

func (r *PendingDNSRing) RecordResponse(mac, resolvedIP, qname string, nowMs int64) {
	if resolvedIP == "" || qname == "" {
		return
	}
	kh := dnsPairHash(mac, resolvedIP)
	idx := kh & 0xff
	r.slots[idx] = PendingDNSSlot{
		RespMonoMs: nowMs,
		KeyHash:    kh,
		QName:      qname,
		Consumed:   false,
	}
}

// MatchHandshake checks if (mac, remoteIP) was resolved via DNS recently:
//   - Returns (dtMs, qname, true) if matched within 15s (allowing ECH QNAME recovery when outer SNI is cloudflare-ech.com!).
func (r *PendingDNSRing) MatchHandshake(mac, remoteIP string, nowMs int64) (int64, string, bool) {
	if remoteIP == "" {
		return 0, "", false
	}
	kh := dnsPairHash(mac, remoteIP)
	slot := &r.slots[kh&0xff]
	if slot.KeyHash != kh || slot.RespMonoMs <= 0 {
		return 0, "", false
	}
	dt := nowMs - slot.RespMonoMs
	if dt < 0 || dt > 15000 {
		return 0, "", false
	}
	wasUnconsumed := !slot.Consumed
	slot.Consumed = true
	if !wasUnconsumed {
		return dt, slot.QName, false // QName still usable for ECH recovery, but don't double-count D2C impulse
	}
	return dt, slot.QName, true
}

// AppBurstExport is serialized in ClientProfile.AppMicroBursts (dpi_state.json) for fg_model & fg_engagement.
type AppBurstExport struct {
	CausalTurns uint32  `json:"causal_turns,omitempty"`
	LightTurns  uint32  `json:"light_turns,omitempty"`
	D2CVerified uint32  `json:"d2c_verified,omitempty"`
	CloseEvents uint32  `json:"close_events,omitempty"`
	D2CImpulse  float64 `json:"d2c_impulse,omitempty"`
	IBTCV       float64 `json:"ibt_cv,omitempty"`
	IBTEntropy  float64 `json:"ibt_entropy,omitempty"`
	Periodicity float64 `json:"periodicity,omitempty"`
}

// MicroBurstTracker is a constant-memory O(1) streaming state machine per (ClientMAC, AppID).
type MicroBurstTracker struct {
	LastPktMonoMs   int64
	StateAnchorMs   int64
	LastTurnEndMs   int64
	LastCausalDNSMs int64

	CurUpBytes        uint32
	CurDnBytes        uint32
	IBTMeanMs         float32
	IBTVarMs2         float32
	D2CImpulse        float32
	CausalTurnsTotal  uint32
	LightTurnsTotal   uint32
	D2CVerifiedTotal  uint32
	CloseEventsTotal  uint32
	UnprovokedMsTotal uint32

	PrevIBT1Cs   uint16
	PrevIBT2Cs   uint16
	PeriodicHits uint16
	SampleCount  uint16

	IBTBins      [8]uint8
	LastDecaySec int32
	State        uint8
	TurnFlags    uint8
	PendingD2CK  uint8
}

func (t *MicroBurstTracker) OnHandshake(nowMs, d2cMs int64, firstConsume, isQUIC bool) {
	t.decayLazy(nowMs)
	if !firstConsume || d2cMs < 0 || d2cMs > 150 {
		return
	}
	if nowMs-t.LastCausalDNSMs < mbRefractoryDNSMs {
		return
	}
	tauFast := int64(80)
	if isQUIC {
		tauFast = 45
	}
	k := 1.0
	if d2cMs > tauFast {
		k = math.Exp(-float64(d2cMs-tauFast) / 50.0)
	}
	t.TurnFlags |= mbFlagPendingD2C
	t.PendingD2CK = uint8(k*255.0 + 0.5)
	t.StateAnchorMs = nowMs
	if t.State == mbStateIdle {
		t.State = mbStateUlArmed
	}
}

func (t *MicroBurstTracker) OnPacket(nowMs int64, isUplink bool, bytes uint32, tcpFlags uint8) {
	// TCP FIN (0x01) or RST (0x04) signals connection teardown (used for swipe-kill Fast Exit)
	if (tcpFlags & 0x05) != 0 {
		t.CloseEventsTotal++
	}
	if bytes == 0 {
		return
	}
	if t.LastPktMonoMs > 0 && nowMs-t.LastPktMonoMs >= mbQuietGapMs {
		t.closeBurst(t.LastPktMonoMs)
	}
	t.LastPktMonoMs = nowMs

	switch t.State {
	case mbStateIdle:
		if isUplink && bytes >= 40 && bytes <= 16384 {
			t.State = mbStateUlArmed
			t.StateAnchorMs = nowMs
			t.CurUpBytes = bytes
			t.CurDnBytes = 0
		} else if !isUplink && bytes >= 512 {
			t.State = mbStateUnprovoked
			t.StateAnchorMs = nowMs
			t.CurDnBytes = bytes
		}
	case mbStateUlArmed:
		if isUplink {
			t.CurUpBytes += bytes
			if t.CurUpBytes > 24576 {
				t.State = mbStateUnprovoked
			}
		} else {
			if nowMs-t.StateAnchorMs <= mbCausalRTTMaxMs {
				t.State = mbStateDlBurst
				t.StateAnchorMs = nowMs
				t.CurDnBytes = bytes
				t.confirmD2C(nowMs)
			} else {
				t.State = mbStateIdle
			}
		}
	case mbStateDlBurst:
		if isUplink {
			t.CurUpBytes += bytes
		} else {
			t.CurDnBytes += bytes
			t.confirmD2C(nowMs)
		}
		if t.CurDnBytes > 512<<10 || nowMs-t.StateAnchorMs > mbMaxBurstDurMs {
			t.State = mbStateUnprovoked
		}
	case mbStateUnprovoked:
		if isUplink {
			t.CurUpBytes += bytes
		} else {
			t.CurDnBytes += bytes
		}
	}
}

func (t *MicroBurstTracker) confirmD2C(nowMs int64) {
	if (t.TurnFlags&mbFlagPendingD2C) != 0 && t.CurDnBytes >= 300 {
		if nowMs-t.LastCausalDNSMs >= mbRefractoryDNSMs {
			t.decayLazy(nowMs)
			t.D2CImpulse += float32(t.PendingD2CK) / 255.0
			t.D2CVerifiedTotal++
			t.LastCausalDNSMs = nowMs
		}
		t.TurnFlags &^= mbFlagPendingD2C
	}
}

func (t *MicroBurstTracker) closeBurst(endMs int64) {
	if t.State == mbStateDlBurst {
		up, dn := t.CurUpBytes, t.CurDnBytes
		isRich := up >= 60 && up <= 24576 && dn >= 2048 && dn <= 512<<10
		diff := int(up) - int(dn)
		if diff < 0 {
			diff = -diff
		}
		isHB := (up+dn < 240) && (diff < 48)
		isLightIM := !isHB && up >= 60 && up <= 4096 && dn >= 250 && dn < 2048
		if isRich || isLightIM {
			t.CausalTurnsTotal++
			if isLightIM {
				t.LightTurnsTotal++
			}
			t.recordIBT(endMs)
		}
	} else if t.State == mbStateUnprovoked && endMs > t.StateAnchorMs {
		t.UnprovokedMsTotal += uint32(endMs - t.StateAnchorMs)
	}
	t.State = mbStateIdle
	t.TurnFlags &^= mbFlagPendingD2C
	t.CurUpBytes, t.CurDnBytes = 0, 0
}

func mbNearEqualCs(a, b uint16) bool {
	if a == 0 || b == 0 {
		return false
	}
	d := int(a) - int(b)
	if d < 0 {
		d = -d
	}
	hi := int(a)
	if int(b) > hi {
		hi = int(b)
	}
	return d*100 <= hi*12
}

func (t *MicroBurstTracker) recordIBT(endMs int64) {
	if t.LastTurnEndMs > 0 {
		ibt := endMs - t.LastTurnEndMs
		if ibt >= mbQuietGapMs && ibt <= mbSessionResetMs {
			if t.SampleCount < 65535 {
				t.SampleCount++
			}
			alpha := float32(0.25)
			if inv := 1.0 / float32(t.SampleCount); inv > alpha {
				alpha = inv
			}
			x := float32(ibt)
			delta := x - t.IBTMeanMs
			t.IBTMeanMs += alpha * delta
			t.IBTVarMs2 = (1.0 - alpha) * (t.IBTVarMs2 + alpha*delta*delta)

			cs := uint16(ibt / 10)
			if mbNearEqualCs(cs, t.PrevIBT1Cs) || mbNearEqualCs(cs, t.PrevIBT2Cs) {
				if t.PeriodicHits < 65535 {
					t.PeriodicHits++
				}
			} else if t.PeriodicHits > 0 {
				t.PeriodicHits--
			}
			t.PrevIBT2Cs = t.PrevIBT1Cs
			t.PrevIBT1Cs = cs

			sc := uint32(ibt / 250)
			if sc == 0 {
				sc = 1
			}
			oct := 31 - bits.LeadingZeros32(sc)
			if oct > 7 {
				oct = 7
			}
			var sum uint16
			for _, v := range t.IBTBins {
				sum += uint16(v)
			}
			if sum >= 64 {
				for i := range t.IBTBins {
					t.IBTBins[i] -= t.IBTBins[i] >> 3
				}
			}
			if t.IBTBins[oct] <= 251 {
				t.IBTBins[oct] += 4
			}
		} else if ibt > mbSessionResetMs {
			t.PeriodicHits = 0
			t.PrevIBT1Cs, t.PrevIBT2Cs = 0, 0
		}
	}
	t.LastTurnEndMs = endMs
}

func (t *MicroBurstTracker) decayLazy(nowMs int64) {
	nowSec := int32(nowMs / 1000)
	if t.LastDecaySec > 0 && nowSec > t.LastDecaySec {
		dt := float64(nowSec - t.LastDecaySec)
		t.D2CImpulse *= float32(math.Exp(-dt * math.Ln2 / mbImpulseHalfLife))
		if t.D2CImpulse < 0.01 {
			t.D2CImpulse = 0
		}
	}
	t.LastDecaySec = nowSec
}

func (t *MicroBurstTracker) Snapshot(nowMs int64) AppBurstExport {
	t.decayLazy(nowMs)
	cv := 0.0
	if t.SampleCount >= 2 && t.IBTMeanMs > 1.0 && t.IBTVarMs2 > 0 {
		cv = math.Sqrt(float64(t.IBTVarMs2)) / float64(t.IBTMeanMs)
	}
	var sum float64
	for _, b := range t.IBTBins {
		sum += float64(b)
	}
	ent := 0.0
	if sum > 0 {
		for _, b := range t.IBTBins {
			if b > 0 {
				p := float64(b) / sum
				ent -= p * math.Log2(p)
			}
		}
		ent /= 3.0 // normalize by log2(8)
	}
	per := 0.0
	if t.SampleCount >= 3 {
		hitRatio := float64(t.PeriodicHits) / float64(t.SampleCount)
		if hitRatio > 1 {
			hitRatio = 1
		}
		per = hitRatio
		if t.SampleCount >= 4 && cv < 0.25 && (1.0-cv*3.0) > per {
			per = 1.0 - cv*3.0
		}
	}
	return AppBurstExport{
		CausalTurns: t.CausalTurnsTotal,
		LightTurns:  t.LightTurnsTotal,
		D2CVerified: t.D2CVerifiedTotal,
		CloseEvents: t.CloseEventsTotal,
		D2CImpulse:  math.Round(float64(t.D2CImpulse)*1000) / 1000,
		IBTCV:       math.Round(cv*1000) / 1000,
		IBTEntropy:  math.Round(ent*1000) / 1000,
		Periodicity: math.Round(per*1000) / 1000,
	}
}
