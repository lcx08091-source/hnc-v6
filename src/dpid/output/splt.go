// Package output - splt.go: HNC v5.37.0 电信级非解密加密流量前 N 包序列特征 (ECA / SPLT)
package output

import (
	"fmt"
	"math/bits"
	"sync/atomic"
)

var ruleReloadGen atomic.Uint64

func bumpRuleReloadGen()            { ruleReloadGen.Add(1) }
func currentRuleReloadGen() uint64  { return ruleReloadGen.Load() }

const SPLTMaxPkts = 10

type SPLTShape uint8

const (
	SPLTShapeUnknown   SPLTShape = 0
	SPLTShapeGameSync  SPLTShape = 1
	SPLTShapeIMControl SPLTShape = 2
	SPLTShapeAPIShort  SPLTShape = 3
	SPLTShapeVideoABR  SPLTShape = 4
	SPLTShapeBulkDL    SPLTShape = 5
	SPLTShapeVoIPMedia SPLTShape = 6
)

// FlowSPLTTracker 24 字节零堆分配内联结构: 仅跟踪连接前 10 个有效载荷包, 第 11 包起 O(1) 早停旁路。
type FlowSPLTTracker struct {
	FirstNs    int64
	LastNs     int64
	Buckets30  uint32
	DirBits10  uint16
	Count      uint8
	BurstTight uint8
	RTTBucket  uint8
	Sealed     bool
}

func spltBucketLen(payloadBytes int) uint32 {
	if payloadBytes <= 31 {
		return 0
	}
	if payloadBytes >= 1350 {
		return 7
	}
	b := uint32(bits.Len32(uint32(payloadBytes))) - 5
	if b > 6 {
		return 6
	}
	return b
}

func (t *FlowSPLTTracker) ObserveL4Packet(realPayloadLen int, isServerToClient bool, nowNs int64) bool {
	if t.Sealed || realPayloadLen <= 0 {
		return false
	}
	idx := t.Count
	if idx == 0 {
		t.FirstNs = nowNs
		t.LastNs = nowNs
	} else {
		dt := nowNs - t.LastNs
		if dt < 0 {
			dt = 0
		}
		if isServerToClient && t.RTTBucket == 0 && t.DirBits10 == 0 {
			switch {
			case dt < 5_000_000:
				t.RTTBucket = 0
			case dt < 30_000_000:
				t.RTTBucket = 1
			case dt < 100_000_000:
				t.RTTBucket = 2
			default:
				t.RTTBucket = 3
			}
		}
		if dt < 2_000_000 {
			t.BurstTight++
		}
		t.LastNs = nowNs
	}

	b := spltBucketLen(realPayloadLen)
	t.Buckets30 |= (b & 0x7) << (uint(idx) * 3)
	if isServerToClient {
		t.DirBits10 |= 1 << uint(idx)
	}
	t.Count = idx + 1
	if t.Count >= SPLTMaxPkts {
		t.Sealed = true
		return true
	}
	return false
}

func (t *FlowSPLTTracker) InferShape(isUDP bool) SPLTShape {
	n := int(t.Count)
	if n < 4 {
		return SPLTShapeUnknown
	}
	var fullMTU, smallPkts, midMedia, downPkts, upPkts, tailFullRun int
	for i := 0; i < n; i++ {
		b := (t.Buckets30 >> (uint(i) * 3)) & 0x7
		down := ((t.DirBits10 >> uint(i)) & 1) != 0
		if down {
			downPkts++
		} else {
			upPkts++
		}
		if b == 7 {
			fullMTU++
			if down {
				tailFullRun++
			}
		} else {
			tailFullRun = 0
		}
		if b <= 2 {
			smallPkts++
		}
		if b >= 2 && b <= 4 {
			midMedia++
		}
	}
	if isUDP && fullMTU == 0 && upPkts >= 2 && downPkts >= 2 {
		if smallPkts >= n/2 {
			return SPLTShapeGameSync
		}
		if midMedia >= (n*2)/3 && t.BurstTight <= 2 {
			return SPLTShapeVoIPMedia
		}
	}
	if tailFullRun >= 5 && upPkts <= 2 && int(t.BurstTight) >= n/2 {
		return SPLTShapeBulkDL
	}
	if fullMTU >= 2 && upPkts >= 3 {
		return SPLTShapeVideoABR
	}
	if fullMTU == 0 && smallPkts >= (n*2)/3 {
		return SPLTShapeIMControl
	}
	return SPLTShapeAPIShort
}

func spltPortClass(isUDP bool, dstPort uint16) uint16 {
	switch {
	case dstPort == 443:
		return 1
	case dstPort == 80 || dstPort == 8080:
		return 2
	case dstPort == 5222 || dstPort == 5223 || dstPort == 5228:
		return 3
	case dstPort == 3478 || dstPort == 19302:
		return 4
	case isUDP && dstPort >= 10000:
		return 100 + (dstPort / 2000)
	default:
		if dstPort < 1024 {
			return 10 + (dstPort & 0x3F)
		}
		return 200 + (dstPort / 4000)
	}
}

func (t *FlowSPLTTracker) PackSig64(isUDP bool, dstPort uint16) uint64 {
	if t.Count < 4 {
		return 0
	}
	shape := t.InferShape(isUDP)
	tight := uint64(0)
	if t.Count > 1 {
		tight = uint64(t.BurstTight) * 3 / uint64(t.Count-1)
		if tight > 3 {
			tight = 3
		}
	}
	iat4 := (uint64(t.RTTBucket&0x3) << 2) | (tight & 0x3)
	protoBit := uint64(0)
	if isUDP {
		protoBit = 1 << 11
	}
	pcls := spltPortClass(isUDP, dstPort)
	return (uint64(t.Count&0xF) << 60) |
		(uint64(shape&0xF) << 56) |
		(iat4 << 52) |
		(uint64(t.DirBits10&0x3FF) << 42) |
		(uint64(t.Buckets30&0x3FFFFFFF) << 12) |
		protoBit | uint64(pcls&0x7FF)
}

func (t *FlowSPLTTracker) PrefixKey(isUDP bool, dstPort uint16) string {
	if t.Count < 4 {
		return ""
	}
	proto := 't'
	if isUDP {
		proto = 'u'
	}
	shape := t.InferShape(isUDP)
	return fmt.Sprintf("splt:%c:s%x:d%02x:b%05x:p%d",
		proto, shape, t.DirBits10&0x3F, t.Buckets30&0x3FFFF, spltPortClass(isUDP, dstPort))
}

func SPLTSoftSimilarity(sigA, sigB uint64) float64 {
	if sigA == 0 || sigB == 0 || ((sigA>>11)&1) != ((sigB>>11)&1) {
		return 0
	}
	n := int((sigA >> 60) & 0xF)
	if nb := int((sigB >> 60) & 0xF); nb < n {
		n = nb
	}
	if n < 4 {
		return 0
	}
	dirA, dirB := (sigA>>42)&0x3FF, (sigA>>42)&0x3FF
	dirB = (sigB >> 42) & 0x3FF
	bktA, bktB := (sigA>>12)&0x3FFFFFFF, (sigB>>12)&0x3FFFFFFF

	var score, maxScore float64
	for i := 0; i < n; i++ {
		w := 1.5
		if i >= 4 {
			w = 1.0
		}
		maxScore += w * 2.0
		if ((dirA >> uint(i)) & 1) == ((dirB >> uint(i)) & 1) {
			score += w
		}
		diff := int((bktA>>(uint(i)*3))&0x7) - int((bktB>>(uint(i)*3))&0x7)
		if diff < 0 {
			diff = -diff
		}
		if diff == 0 {
			score += w
		} else if diff == 1 {
			score += w * 0.65
		}
	}
	if ((sigA >> 56) & 0xF) == ((sigB >> 56) & 0xF) {
		score += 1.5
	}
	return score / (maxScore + 1.5)
}
