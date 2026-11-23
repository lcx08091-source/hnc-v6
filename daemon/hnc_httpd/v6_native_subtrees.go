// v6_native_subtrees.go — HNC v6.0.0 · Vector (M8 全原生数据面收官):
//  1. 单应用限速二级子树 1:9001..1:9998 + 1:9eXX 防逃逸默认兜底子类 + POSTROUTING CONNMARK 顺序保护;
//  2. 三档动态延迟联动应用 QoS 子树 1:a0XX (根据实时 RTT/抖动在常规 50/35/15 与团战抗抖 70/20/10 之间平滑自适应调节);
//  3. 开机冷启全量原生恢复 NativeFullRestoreV6 (多口并发同步设备类 + 二级子树 + 双栈防火墙);
//  4. 原生 AF_NETLINK RTM_GETNEIGH IPv6 邻居探测与 128-bit u32 动态过滤器同步。
//
// 100% 标准库 syscall + encoding/binary.LittleEndian, 零第三方依赖, 零 unsafe.Pointer, 32 位 ARM 安全。

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 单应用限速二级子树 minor 段: 1:9001 .. 1:9998 (避开默认类 1:9999)
	v6AppLimitMinorStart uint16 = 0x9001
	v6AppLimitMinorEnd   uint16 = 0x9998
	v6AppLimitMaxSlots   int    = 63 // 6-bit [31:26] 0xfc000000 -> slot 1..63
	v6AppLimitDefBase    uint16 = 0x9e00
	v6AppLimitCBurstCapB uint32 = 32 * 1024 // 32 KiB cburst 上限, 抑制突发视频流穿透限速桶

	// 三档应用感知 QoS 二级子树基址: minor = 0xa000 + mid*4 + tier(1..3), 叶子 major = 0xb000 + mid*4 + tier
	v6AppQoSMinorBase uint16 = 0xa000
	v6AppQoSLeafBase  uint16 = 0xb000
	v6AppQoSTier1Mark uint32 = uint32(0x01000000)
	v6AppQoSTier3Mark uint32 = uint32(0x03000000)
	v6InnerPrioAppLim uint16 = 1
	v6InnerPrioAppQoS uint16 = 2
	v6InnerPrioDefAll uint16 = 9

	// 动态 QoS 延迟联动阈值 (毫秒)
	v6QoSCalmJitterMs   = 12.0
	v6QoSCombatJitterMs = 35.0
	v6QoSCalmDeltaRTTMs = 15.0
	v6QoSCombatDeltaMs  = 45.0
	v6QoSRatioDeadband  = 3 // 档位变化 >= 3% 才触发内核 RTM_NEWTCLASS 原地更新, 消除微幅振荡

	// IPv6 原生邻居同步常量
	v6IPv6SrcHdrOff int = 8  // IPv6 报头源地址偏移 (8..24)
	v6IPv6DstHdrOff int = 24 // IPv6 报头目的地址偏移 (24..40)
	v6IPv6MaxAddrs  int = 16
)

// QoSDynamicRatios 表示三档应用 QoS 的实时保证带宽比例 (严格满足 Tier1Pct + Tier2Pct + Tier3Pct == 100)。
type QoSDynamicRatios struct {
	Tier1Pct      int     `json:"tier1_pct"`      // 实时游戏/语音档: 常规 50% -> 团战抗抖 70%
	Tier2Pct      int     `json:"tier2_pct"`      // 交互浏览默认档: 常规 35% -> 团战抗抖 20%
	Tier3Pct      int     `json:"tier3_pct"`      // 后台下载大流档: 常规 15% -> 团战抗抖 10%
	Mode          string  `json:"mode"`           // "normal_50_35_15" | "adaptive_blend" | "combat_70_20_10"
	StressFactor  float64 `json:"stress_factor"`  // 0.0 .. 1.0
	TriggerJitter float64 `json:"trigger_jitter"` // ms
	TriggerDelta  float64 `json:"trigger_delta"`  // ms
}

// V6AppLimitSlotAssignment 描述单条 (设备, 应用) 限速分配到的正交槽位、子类号与目的 IP 列表。
type V6AppLimitSlotAssignment struct {
	Slot        int      `json:"slot"` // 1..63 -> mark (slot << 26) / 0xfc000000
	MAC         string   `json:"mac"`
	Mid         int      `json:"mid"`
	ParentMinor uint16   `json:"parent_minor"`
	ClassMinor  uint16   `json:"class_minor"` // 0x9001 + slot - 1
	ClassID     string   `json:"class_id"`
	MarkVal     uint32   `json:"mark_val"`
	AppID       string   `json:"app_id"`
	RateBps     uint64   `json:"rate_bps"`
	CeilBps     uint64   `json:"ceil_bps"`
	IPv4Targets []string `json:"ipv4_targets,omitempty"`
	IPv6Targets []string `json:"ipv6_targets,omitempty"`
}

// V6NativeRestoreReport 汇总一次 NativeFullRestoreV6 全量原生恢复的执行明细。
type V6NativeRestoreReport struct {
	RestoredAtMs     int64            `json:"restored_at_ms"`
	DurationMs       float64          `json:"duration_ms"`
	DownstreamIfaces []string         `json:"downstream_ifaces"`
	DevicesRestored  int              `json:"devices_restored"`
	AppLimitClasses  int              `json:"app_limit_classes"`
	AppQoSDevices    int              `json:"app_qos_devices"`
	IPv6AddrsSynced  int              `json:"ipv6_addrs_synced"`
	QoSRatios        QoSDynamicRatios `json:"qos_ratios"`
	NetlinkMessages  int              `json:"netlink_messages"`
	FirewallUpdated  bool             `json:"firewall_updated"`
	Warnings         []string         `json:"warnings,omitempty"`
}

// v6SubtreeController 维护 M8 二级子树与动态 QoS 平滑调节状态。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子计数器位于结构体顶部 offset 0。
type v6SubtreeController struct {
	appLimitApplies atomic.Uint64
	appQoSApplies   atomic.Uint64
	dynamicTunes    atomic.Uint64
	fullRestores    atomic.Uint64
	v6NeighSyncs    atomic.Uint64

	mu          sync.RWMutex
	ewmaStress  float64
	ewmaInit    bool
	lastRatios  QoSDynamicRatios
	lastRestore V6NativeRestoreReport
}

var globalV6Subtrees = &v6SubtreeController{
	lastRatios: QoSDynamicRatios{
		Tier1Pct: 50,
		Tier2Pct: 35,
		Tier3Pct: 15,
		Mode:     "normal_50_35_15",
	},
}

// ── 1. 三档动态延迟联动算法 (50/35/15 <-> 70/20/10 平滑无振荡调节) ─────────

// ComputeDynamicQoSRatios 根据实时 RTT 抖动(jitterMs)与排队延迟增量(deltaRTTMs)计算三档比例:
//   - 平稳期 (jitter <= 12ms 且 deltaRTT <= 15ms): 常规 50 / 35 / 15;
//   - 拥塞/团战期 (jitter >= 35ms 或 deltaRTT >= 45ms): 团战抗抖 70 / 20 / 10;
//   - 过渡期: 按最大归一化压力因子线性插值并保证三档严格闭合为 100%。
func ComputeDynamicQoSRatios(jitterMs, deltaRTTMs float64) QoSDynamicRatios {
	if math.IsNaN(jitterMs) || math.IsInf(jitterMs, 0) || jitterMs < 0 {
		jitterMs = 0
	}
	if math.IsNaN(deltaRTTMs) || math.IsInf(deltaRTTMs, 0) || deltaRTTMs < 0 {
		deltaRTTMs = 0
	}

	sJitter := 0.0
	if jitterMs > v6QoSCalmJitterMs {
		sJitter = (jitterMs - v6QoSCalmJitterMs) / (v6QoSCombatJitterMs - v6QoSCalmJitterMs)
	}
	sDelta := 0.0
	if deltaRTTMs > v6QoSCalmDeltaRTTMs {
		sDelta = (deltaRTTMs - v6QoSCalmDeltaRTTMs) / (v6QoSCombatDeltaMs - v6QoSCalmDeltaRTTMs)
	}
	stress := math.Max(sJitter, sDelta)
	if stress < 0 {
		stress = 0
	}
	if stress > 1 {
		stress = 1
	}

	return ratiosFromStress(stress, jitterMs, deltaRTTMs)
}

func ratiosFromStress(stress, jitterMs, deltaRTTMs float64) QoSDynamicRatios {
	t1 := 50 + int(math.Round(20.0*stress)) // 50 -> 70
	t3 := 15 - int(math.Round(5.0*stress))  // 15 -> 10
	if t1 < 50 {
		t1 = 50
	}
	if t1 > 70 {
		t1 = 70
	}
	if t3 < 10 {
		t3 = 10
	}
	if t3 > 15 {
		t3 = 15
	}
	t2 := 100 - t1 - t3 // 35 -> 20, 恒定闭合 100%

	mode := "adaptive_blend"
	switch {
	case t1 <= 50 && t2 >= 35:
		mode = "normal_50_35_15"
	case t1 >= 70 && t3 <= 10:
		mode = "combat_70_20_10"
	}
	return QoSDynamicRatios{
		Tier1Pct:      t1,
		Tier2Pct:      t2,
		Tier3Pct:      t3,
		Mode:          mode,
		StressFactor:  math.Round(stress*1000) / 1000,
		TriggerJitter: math.Round(jitterMs*100) / 100,
		TriggerDelta:  math.Round(deltaRTTMs*100) / 100,
	}
}

// SmoothStepDynamicQoS 带快攻慢放 EWMA 滤波与死区抑制的平滑比例步进器:
//   - 延迟突刺上升时快速响应 (alphaUp = 0.65), 迅速切入 70/20/10 护航实时包;
//   - 抖动消退时缓慢回落 (alphaDown = 0.25), 防止刚退回 50/35/15 立刻二次抖动。
func (c *v6SubtreeController) SmoothStepDynamicQoS(jitterMs, deltaRTTMs float64) (ratios QoSDynamicRatios, changed bool) {
	inst := ComputeDynamicQoSRatios(jitterMs, deltaRTTMs)

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ewmaInit {
		c.ewmaStress = inst.StressFactor
		c.ewmaInit = true
	} else if inst.StressFactor >= c.ewmaStress {
		c.ewmaStress = 0.65*inst.StressFactor + 0.35*c.ewmaStress
	} else {
		c.ewmaStress = 0.25*inst.StressFactor + 0.75*c.ewmaStress
	}
	if c.ewmaStress < 0.02 {
		c.ewmaStress = 0
	} else if c.ewmaStress > 0.98 {
		c.ewmaStress = 1
	}

	cand := ratiosFromStress(c.ewmaStress, jitterMs, deltaRTTMs)
	diff1 := cand.Tier1Pct - c.lastRatios.Tier1Pct
	if diff1 < 0 {
		diff1 = -diff1
	}
	// 精确到达两端极值 (50/35/15 或 70/20/10) 或比例变动达到死区阈值时才发布更新
	endpointSwitch := (cand.Mode != c.lastRatios.Mode) && (cand.Mode == "normal_50_35_15" || cand.Mode == "combat_70_20_10")
	if diff1 >= v6QoSRatioDeadband || endpointSwitch {
		c.lastRatios = cand
		c.dynamicTunes.Add(1)
		return cand, true
	}
	return c.lastRatios, false
}

// ── 2. 通用 u32 全通兜底过滤器 & 128-bit IPv6 u32 过滤器报文构造器 ──────────

// buildU32CatchAllFilterMsg 构造 `tc filter ... prio <prio> u32 match u32 0 0 flowid <classID>` 报文。
// 用于 parent 1:<cid> 下的 prio 9 默认兜底路由(将未命中单应用限速/Tier1/Tier3 的流量兜底至 1:9eXX 或 Tier2 1:a0XX)。
func buildU32CatchAllFilterMsg(seq uint32, ifindex int, parent uint32, prio, ethProto uint16, classID uint32) []byte {
	var sel [rtnlU32SelHdrSize + rtnlU32KeySize]byte
	sel[0] = rtnlTcU32Terminal // flags = TC_U32_TERMINAL
	sel[2] = 1                 // nkeys = 1 (mask=0, val=0, off=0 全零即匹配任意报文)

	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaU32ClassID, classID)
	opts = rtnlPutAttr(opts, rtnlTcaU32Sel, sel[:])
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "u32")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	info := (uint32(prio) << 16) | uint32(rtnlHtons(ethProto))
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewTFilter, flags, seq, ifindex, 0, parent, info, attrs)
}

// buildFqCodelCustomMsg 构造可自定义 target/interval/quantum/limit 的 fq_codel 叶子队列报文。
func buildFqCodelCustomMsg(seq uint32, ifindex int, parent, leafHandle, targetUs, intervalUs, quantum, limit uint32) []byte {
	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelTarget, targetUs)
	opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelInterval, intervalUs)
	opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelQuantum, quantum)
	opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelLimit, limit)
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "fq_codel")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewQdisc, flags, seq, ifindex, leafHandle, parent, 0, attrs)
}

// BuildU32IPv6FilterMsg 使用纯 binary.LittleEndian 编码 128-bit IPv6 /128 匹配的 u32 过滤器报文:
//   - struct tc_u32_sel(16B) + 4 * struct tc_u32_key(64B) = 80B;
//   - isUplink=false (下行热点口): 匹配 IPv6 目的地址 dst (offset 24, 28, 32, 36);
//   - isUplink=true  (上行 ifb0):   匹配 IPv6 源地址 src   (offset 8, 12, 16, 20)。
func BuildU32IPv6FilterMsg(seq uint32, ifindex int, parent uint32, prio uint16, ip6 net.IP, isUplink bool, classID uint32) ([]byte, error) {
	if ip6 == nil || ip6.To4() != nil {
		return nil, fmt.Errorf("invalid IPv6 address %v", ip6)
	}
	v6 := ip6.To16()
	if len(v6) != 16 {
		return nil, fmt.Errorf("invalid IPv6 16-byte form %v", ip6)
	}

	var sel [rtnlU32SelHdrSize + 4*rtnlU32KeySize]byte
	sel[0] = rtnlTcU32Terminal // flags = TC_U32_TERMINAL
	sel[2] = 4                 // nkeys = 4 (4 * 32-bit = 128-bit)

	baseOff := v6IPv6DstHdrOff
	if isUplink {
		baseOff = v6IPv6SrcHdrOff
	}
	for k := 0; k < 4; k++ {
		kOff := rtnlU32SelHdrSize + k*rtnlU32KeySize
		word := v6IPv4BytesToWireLE32(v6[k*4 : k*4+4])
		binary.LittleEndian.PutUint32(sel[kOff:kOff+4], uint32(0xffffffff))
		binary.LittleEndian.PutUint32(sel[kOff+4:kOff+8], word)
		binary.LittleEndian.PutUint32(sel[kOff+8:kOff+12], uint32(baseOff+k*4))
		binary.LittleEndian.PutUint32(sel[kOff+12:kOff+16], 0)
	}

	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaU32ClassID, classID)
	opts = rtnlPutAttr(opts, rtnlTcaU32Sel, sel[:])
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "u32")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	info := (uint32(prio) << 16) | uint32(rtnlHtons(rtnlEthPIPv6))
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate)
	return rtnlBuildTCMsg(rtnlNewTFilter, flags, seq, ifindex, 0, parent, info, attrs), nil
}

// ── 3. 三档应用感知 QoS 二级子树 (1:a0XX) 报文构造器 ────────────────────────

func appQoSChildMinor(mid, tier int) (uint16, error) {
	if mid < 1 || mid > 99 || tier < 1 || tier > 3 {
		return 0, fmt.Errorf("invalid app_qos (mid=%d, tier=%d)", mid, tier)
	}
	return v6AppQoSMinorBase + uint16(mid*4+tier), nil
}

func appQoSLeafMajor(mid, tier int) uint32 {
	return uint32(v6AppQoSLeafBase+uint16(mid*4+tier)) << 16
}

// BuildAppQoSSubtreeNetlinkBatch 为单台设备(mid 1..99)构造完整的三档动态应用 QoS 二级子树 Netlink 报文批次:
//   - 父节点: 1:<cid> (rate=parentRateBps, ceil=parentCeilBps);
//   - 子节点:
//     Tier 1 (1:a0X1, prio 0): rate = parentRate * Tier1Pct%, ceil = parentCeil, 微秒级紧凑 fq_codel(target=2.5ms, quantum=300);
//     Tier 2 (1:a0X2, prio 1): rate = parentRate * Tier2Pct%, ceil = parentCeil, 标准 fq_codel(target=5ms, quantum=1514);
//     Tier 3 (1:a0X3, prio 2): rate = parentRate * Tier3Pct%, ceil = parentCeil, 后台 fq_codel(target=8ms, quantum=1514);
//   - 二级过滤器(挂在 parent 1:<cid> prio 2 & prio 9, 让位 prio 1 单应用限速 1:9001+ 无损共存!):
//     prio 2 handle 0x01000000/0x03000000 fw -> Tier 1;
//     prio 2 handle 0x03000000/0x03000000 fw -> Tier 3;
//     prio 9 u32 match u32 0 0               -> Tier 2。
func BuildAppQoSSubtreeNetlinkBatch(
	ifindex, mid int,
	parentRateBps, parentCeilBps uint64,
	devMarkVal, devMarkMask uint32,
	ratios QoSDynamicRatios,
	tickInUsec float64,
) ([][]byte, error) {
	if ifindex <= 0 {
		return nil, fmt.Errorf("BuildAppQoSSubtreeNetlinkBatch: invalid ifindex %d", ifindex)
	}
	parentMinor, err := htbClassMinorForMid(mid)
	if err != nil {
		return nil, err
	}
	if parentRateBps == 0 {
		parentRateBps = DefaultHTBRootRateBps
	}
	if parentCeilBps == 0 {
		parentCeilBps = parentRateBps
	}
	if devMarkMask == 0 {
		devMarkMask = DefaultDevMarkMask
	}
	if ratios.Tier1Pct+ratios.Tier2Pct+ratios.Tier3Pct != 100 || ratios.Tier1Pct <= 0 || ratios.Tier2Pct <= 0 || ratios.Tier3Pct <= 0 {
		ratios = ComputeDynamicQoSRatios(0, 0)
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}

	parentHandle := rtnlHtbRootMaj | uint32(parentMinor)
	var msgs [][]byte

	// 1. 确保父设备类 1:<cid> 就位 + 根 fw 过滤器指向 1:<cid>
	msgs = append(msgs, buildHTBClassUpsertMsg(
		rtnlNextSeq(), ifindex, rtnlHtbRootCls, parentHandle,
		parentRateBps, parentCeilBps, 0, 0, 0, 3, tickInUsec,
	))
	if (devMarkVal & devMarkMask) != 0 {
		msgs = append(msgs, buildFwFilterMsg(
			rtnlNextSeq(), ifindex, rtnlHtbRootMaj,
			rtnlFilterPrioFW, rtnlEthPAll, devMarkVal, devMarkMask, parentHandle,
		))
	}

	// 2. 若之前存在 1:9eXX 单应用兜底子类, 先清理(三档 QoS 下未限速应用自动落入 Tier 2)
	defMinor := v6AppLimitDefBase + uint16(mid)
	defHandle := rtnlHtbRootMaj | uint32(defMinor)
	msgs = append(msgs, buildDelFilterMsg(rtnlNextSeq(), ifindex, parentHandle, 0, v6InnerPrioDefAll, rtnlEthPAll, ""))
	msgs = append(msgs, rtnlBuildTCMsg(rtnlDelTClass, rtnlFRequest|rtnlFAck, rtnlNextSeq(), ifindex, defHandle, parentHandle, 0, nil))

	pcts := [3]int{ratios.Tier1Pct, ratios.Tier2Pct, ratios.Tier3Pct}
	var tierHandles [3]uint32
	for t := 1; t <= 3; t++ {
		cMinor, mErr := appQoSChildMinor(mid, t)
		if mErr != nil {
			return nil, mErr
		}
		cHandle := rtnlHtbRootMaj | uint32(cMinor)
		tierHandles[t-1] = cHandle

		rBps := (parentRateBps * uint64(pcts[t-1])) / 100
		if rBps < 125 { // >= 1 kbit/s
			rBps = 125
		}
		if rBps > parentCeilBps {
			rBps = parentCeilBps
		}
		prio := uint32(t - 1) // Tier1->0, Tier2->1, Tier3->2
		msgs = append(msgs, buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, parentHandle, cHandle,
			rBps, parentCeilBps, 0, 0, 0, prio, tickInUsec,
		))

		leafMaj := appQoSLeafMajor(mid, t)
		switch t {
		case 1:
			// Tier 1 游戏/VoIP 专属低目标延迟 fq_codel (target=2.5ms, interval=50ms, quantum=300)
			msgs = append(msgs, buildFqCodelCustomMsg(rtnlNextSeq(), ifindex, cHandle, leafMaj, 2500, 50_000, 300, 512))
		case 2:
			msgs = append(msgs, buildFqCodelCustomMsg(rtnlNextSeq(), ifindex, cHandle, leafMaj, 5000, 100_000, 1514, 1024))
		default:
			msgs = append(msgs, buildFqCodelCustomMsg(rtnlNextSeq(), ifindex, cHandle, leafMaj, 8000, 100_000, 1514, 1024))
		}
	}

	// 3. 挂载二级分类器: prio 2 fw (Tier 1 & Tier 3) + prio 9 u32 全通兜底 (Tier 2)
	msgs = append(msgs, buildFwFilterMsg(
		rtnlNextSeq(), ifindex, parentHandle,
		v6InnerPrioAppQoS, rtnlEthPAll, v6AppQoSTier1Mark, DefaultAppQoSMarkMask, tierHandles[0],
	))
	msgs = append(msgs, buildFwFilterMsg(
		rtnlNextSeq(), ifindex, parentHandle,
		v6InnerPrioAppQoS, rtnlEthPAll, v6AppQoSTier3Mark, DefaultAppQoSMarkMask, tierHandles[2],
	))
	msgs = append(msgs, buildU32CatchAllFilterMsg(
		rtnlNextSeq(), ifindex, parentHandle,
		v6InnerPrioDefAll, rtnlEthPAll, tierHandles[1],
	))

	return msgs, nil
}

// ── 4. 单应用限速二级子树 (1:9001..1:9998 + 1:9eXX) 报文与防火墙构造器 ──────

// BuildAppLimitSubtreeNetlinkBatch 为单台设备下的一组受限应用构造二级 HTB 子树报文批次:
//   - 每个应用子类 1:9001+ 严格挂在对应设备的 1:<cid> 下, ceil 严格钳制 <= parentCeilBps,
//     cburst 独立收紧至 <= 32KiB;
//   - 在 parent 1:<cid> 挂载 prio 1 handle <slot<<26>/0xfc000000 fw -> 1:<appMinor>;
//   - 当 hasAppQoS=false 时, 自动补齐 1:9eXX 默认兜底子类 + prio 9 u32 兜底过滤器, 根绝未限速流量逃逸至 1:9999!
func BuildAppLimitSubtreeNetlinkBatch(
	ifindex, mid int,
	parentRateBps, parentCeilBps uint64,
	devMarkVal, devMarkMask uint32,
	assignments []V6AppLimitSlotAssignment,
	hasAppQoS bool,
	tickInUsec float64,
) ([][]byte, error) {
	if ifindex <= 0 {
		return nil, fmt.Errorf("BuildAppLimitSubtreeNetlinkBatch: invalid ifindex %d", ifindex)
	}
	parentMinor, err := htbClassMinorForMid(mid)
	if err != nil {
		return nil, err
	}
	if parentRateBps == 0 {
		parentRateBps = DefaultHTBRootRateBps
	}
	if parentCeilBps == 0 {
		parentCeilBps = parentRateBps
	}
	if devMarkMask == 0 {
		devMarkMask = DefaultDevMarkMask
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}

	parentHandle := rtnlHtbRootMaj | uint32(parentMinor)
	var msgs [][]byte

	// 1. 确保父设备类 1:<cid> 存在
	msgs = append(msgs, buildHTBClassUpsertMsg(
		rtnlNextSeq(), ifindex, rtnlHtbRootCls, parentHandle,
		parentRateBps, parentCeilBps, 0, 0, 0, 3, tickInUsec,
	))
	if (devMarkVal & devMarkMask) != 0 {
		msgs = append(msgs, buildFwFilterMsg(
			rtnlNextSeq(), ifindex, rtnlHtbRootMaj,
			rtnlFilterPrioFW, rtnlEthPAll, devMarkVal, devMarkMask, parentHandle,
		))
	}

	// 2. 逐条创建 1:9001+ 应用限速子类 + fq_codel 叶子 + prio 1 正交高位 fw 过滤器
	var reservedSum uint64
	for _, asg := range assignments {
		if asg.Mid != mid || asg.Slot < 1 || asg.Slot > v6AppLimitMaxSlots {
			continue
		}
		appMinor := v6AppLimitMinorStart + uint16(asg.Slot-1)
		if asg.ClassMinor >= v6AppLimitMinorStart && asg.ClassMinor <= v6AppLimitMinorEnd {
			appMinor = asg.ClassMinor
		}
		if appMinor > v6AppLimitMinorEnd {
			return nil, fmt.Errorf("app limit minor 0x%x exceeds 0x%x", appMinor, v6AppLimitMinorEnd)
		}
		appHandle := rtnlHtbRootMaj | uint32(appMinor)

		ceilBps := asg.CeilBps
		if ceilBps == 0 {
			ceilBps = asg.RateBps
		}
		if ceilBps == 0 {
			continue
		}
		// 铁律: 单应用 ceil 绝不能突破父设备总上限 parentCeilBps!
		if ceilBps > parentCeilBps {
			ceilBps = parentCeilBps
		}
		rateBps := asg.RateBps
		if rateBps == 0 || rateBps > ceilBps {
			rateBps = ceilBps
		}
		reservedSum += rateBps

		burst := hncBurstBytesForRate(rateBps, true)
		cburst := hncBurstBytesForRate(ceilBps, true)
		if cburst > v6AppLimitCBurstCapB {
			cburst = v6AppLimitCBurstCapB
		}
		if burst > cburst {
			burst = cburst
		}

		msgs = append(msgs, buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, parentHandle, appHandle,
			rateBps, ceilBps, burst, cburst, 0, 1, tickInUsec,
		))
		leafMaj := uint32(appMinor) << 16
		msgs = append(msgs, buildFqCodelLeafMsg(rtnlNextSeq(), ifindex, appHandle, leafMaj, true))

		markVal := (uint32(asg.Slot) << 26) & DefaultAppLimitMarkMask
		msgs = append(msgs, buildFwFilterMsg(
			rtnlNextSeq(), ifindex, parentHandle,
			v6InnerPrioAppLim, rtnlEthPAll, markVal, DefaultAppLimitMarkMask, appHandle,
		))
	}

	// 3. 若该设备未开 app_qos, 建立 1:9eXX 默认兜底子类 + prio 9 u32 兜底过滤器防逃逸至 1:9999
	if !hasAppQoS {
		defMinor := v6AppLimitDefBase + uint16(mid)
		defHandle := rtnlHtbRootMaj | uint32(defMinor)
		defRate := parentRateBps / 2
		if parentRateBps > reservedSum && parentRateBps-reservedSum > defRate {
			defRate = parentRateBps - reservedSum
		}
		if defRate < 125_000 { // 至少 1000 kbit/s
			defRate = 125_000
		}
		if defRate > parentCeilBps {
			defRate = parentCeilBps
		}
		msgs = append(msgs, buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, parentHandle, defHandle,
			defRate, parentCeilBps, 0, 0, 0, 2, tickInUsec,
		))
		msgs = append(msgs, buildFqCodelLeafMsg(rtnlNextSeq(), ifindex, defHandle, uint32(defMinor)<<16, true))
		msgs = append(msgs, buildU32CatchAllFilterMsg(
			rtnlNextSeq(), ifindex, parentHandle,
			v6InnerPrioDefAll, rtnlEthPAll, defHandle,
		))
	}

	return msgs, nil
}

// BuildAppLimitFirewallPayloads 构造双栈 iptables-restore / ip6tables-restore --noflush 载荷:
//   - HNC_APP_LIMIT_UP / HNC_APP_LIMIT_DOWN: 对 [31:26] 0xfc000000 正交打标并即时写入 CONNMARK --save-mark
//     (确保在 POSTROUTING HNC_EGRESS_FIX 清除高 8 位前持久化进 conntrack, 后续下行包零漏标!);
//   - HNC_QUIC_APPLIM: 对受限应用目的 IP 的 UDP 443 返回 REJECT, 引导 HTTP/3 平滑回落 TCP 精确控速。
func BuildAppLimitFirewallPayloads(assignments []V6AppLimitSlotAssignment, devIPv4ByMAC map[string]string, devIPv6ByMAC map[string][]string) ([]byte, []byte) {
	var v4, v6 bytes.Buffer

	v4.WriteString("*mangle\n:HNC_APP_LIMIT_UP - [0:0]\n:HNC_APP_LIMIT_DOWN - [0:0]\n")
	v6.WriteString("*mangle\n:HNC_APP_LIMIT_UP - [0:0]\n:HNC_APP_LIMIT_DOWN - [0:0]\n")

	// 先由 CONNMARK 恢复已建立流的高 6 位 [31:26] 应用限速标记(严守低 26 位不动)
	fmt.Fprintf(&v4, "-A HNC_APP_LIMIT_DOWN -m connmark ! --mark 0x0/0x%08x -j CONNMARK --restore-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)
	fmt.Fprintf(&v6, "-A HNC_APP_LIMIT_DOWN -m connmark ! --mark 0x0/0x%08x -j CONNMARK --restore-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)

	for _, asg := range assignments {
		if asg.Slot < 1 || asg.Slot > v6AppLimitMaxSlots {
			continue
		}
		markVal := (uint32(asg.Slot) << 26) & DefaultAppLimitMarkMask
		xmark := fmt.Sprintf("0x%08x/0x%08x", markVal, DefaultAppLimitMarkMask)
		clientV4 := strings.TrimSpace(devIPv4ByMAC[asg.MAC])

		for _, dstIP := range asg.IPv4Targets {
			fmt.Fprintf(&v4, "-A HNC_APP_LIMIT_UP -m mac --mac-source %s -d %s/32 -j MARK --set-xmark %s\n", asg.MAC, dstIP, xmark)
			if clientV4 != "" {
				fmt.Fprintf(&v4, "-A HNC_APP_LIMIT_DOWN -s %s/32 -d %s/32 -j MARK --set-xmark %s\n", dstIP, clientV4, xmark)
			}
		}
		for _, dstV6 := range asg.IPv6Targets {
			fmt.Fprintf(&v6, "-A HNC_APP_LIMIT_UP -m mac --mac-source %s -d %s/128 -j MARK --set-xmark %s\n", asg.MAC, dstV6, xmark)
			for _, cliV6 := range devIPv6ByMAC[asg.MAC] {
				fmt.Fprintf(&v6, "-A HNC_APP_LIMIT_DOWN -s %s/128 -d %s/128 -j MARK --set-xmark %s\n", dstV6, cliV6, xmark)
			}
		}
	}

	// 将新打上的 [31:26] 应用标记即时锁入 CONNMARK (先于 POSTROUTING HNC_EGRESS_FIX!)
	fmt.Fprintf(&v4, "-A HNC_APP_LIMIT_UP -m mark ! --mark 0x0/0x%08x -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)
	fmt.Fprintf(&v4, "-A HNC_APP_LIMIT_DOWN -m mark ! --mark 0x0/0x%08x -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)
	fmt.Fprintf(&v6, "-A HNC_APP_LIMIT_UP -m mark ! --mark 0x0/0x%08x -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)
	fmt.Fprintf(&v6, "-A HNC_APP_LIMIT_DOWN -m mark ! --mark 0x0/0x%08x -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
		DefaultAppLimitMarkMask, DefaultAppLimitMarkMask, DefaultAppLimitMarkMask)
	v4.WriteString("COMMIT\n")
	v6.WriteString("COMMIT\n")

	// *filter 表: 受限应用 UDP/443 QUIC 平滑回落 TCP
	v4.WriteString("*filter\n:HNC_QUIC_APPLIM - [0:0]\n")
	v6.WriteString("*filter\n:HNC_QUIC_APPLIM - [0:0]\n")
	for _, asg := range assignments {
		for _, dstIP := range asg.IPv4Targets {
			fmt.Fprintf(&v4, "-A HNC_QUIC_APPLIM -m mac --mac-source %s -p udp --dport 443 -d %s/32 -j REJECT --reject-with icmp-port-unreachable\n", asg.MAC, dstIP)
		}
		for _, dstV6 := range asg.IPv6Targets {
			fmt.Fprintf(&v6, "-A HNC_QUIC_APPLIM -m mac --mac-source %s -p udp --dport 443 -d %s/128 -j REJECT --reject-with icmp6-port-unreachable\n", asg.MAC, dstV6)
		}
	}
	v4.WriteString("COMMIT\n")
	v6.WriteString("COMMIT\n")

	return v4.Bytes(), v6.Bytes()
}

// PlanAppLimitSlotAssignments 从 data/app_limits.json + run/ip_app_map.flat + run/dpi_ipname.json
// 规划最多 63 个正交单应用限速槽位(自动过滤多应用共享 CDN IP)。
func (s *server) PlanAppLimitSlotAssignments(midByMAC map[string]int) []V6AppLimitSlotAssignment {
	if s == nil || s.hncDir == "" {
		return nil
	}
	af := loadAppLimits(s.hncDir)
	if len(af.Items) == 0 {
		return nil
	}
	appIPs := loadIPAppFlat(s.hncDir)
	includeShared := appLimitIncludeShared(s.hncDir)
	nameApp := ipNameAppMap(s.loadIPNames())

	out := make([]V6AppLimitSlotAssignment, 0, len(af.Items))
	slot := 1
	for _, it := range af.Items {
		if slot > v6AppLimitMaxSlots {
			break
		}
		mac := strings.ToLower(strings.TrimSpace(it.MAC))
		mid := midByMAC[mac]
		if !macRE.MatchString(mac) || mid < 1 || mid > 99 || it.DownMbps <= 0 || math.IsNaN(it.DownMbps) || math.IsInf(it.DownMbps, 0) {
			continue
		}
		pMinor, err := htbClassMinorForMid(mid)
		if err != nil {
			continue
		}
		bps, err := mbpsStrToBytesPerSec(fmt.Sprintf("%g", it.DownMbps))
		if err != nil || bps == 0 {
			continue
		}
		kept, _ := appLimitSplitShared(it.AppID, appIPs[it.AppID], nameApp, includeShared)
		var v4s, v6s []string
		for _, rawIP := range kept {
			ip := net.ParseIP(strings.TrimSpace(rawIP))
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if ip.To4() != nil {
				v4s = append(v4s, ip.To4().String())
			} else {
				v6s = append(v6s, ip.String())
			}
		}
		sort.Strings(v4s)
		sort.Strings(v6s)
		cMinor := v6AppLimitMinorStart + uint16(slot-1)
		out = append(out, V6AppLimitSlotAssignment{
			Slot:        slot,
			MAC:         mac,
			Mid:         mid,
			ParentMinor: pMinor,
			ClassMinor:  cMinor,
			ClassID:     fmt.Sprintf("1:%x", cMinor),
			MarkVal:     (uint32(slot) << 26) & DefaultAppLimitMarkMask,
			AppID:       it.AppID,
			RateBps:     bps,
			CeilBps:     bps,
			IPv4Targets: v4s,
			IPv6Targets: v6s,
		})
		slot++
	}
	return out
}

// ── 5. 原生 AF_NETLINK RTM_GETNEIGH IPv6 邻居采集与动态过滤器同步 ──────────

// buildGetNeighIPv6DumpMsg 构造 RTM_GETNEIGH (AF_INET6, NLM_F_REQUEST|NLM_F_DUMP) 报文:
// nlmsghdr(16B) + struct ndmsg(12B)。
const (
	rtnlNewNeigh uint16 = 28   // RTM_NEWNEIGH
	rtnlGetNeigh uint16 = 30   // RTM_GETNEIGH
	rtnlAfInet6  uint8  = 10   // AF_INET6
	ndaCacheInfo uint16 = 3    // NDA_CACHEINFO (struct nda_cacheinfo: confirmed/used/updated/refcnt u32)
	nudProbe     uint16 = 0x10 // NUD_PROBE
	nudPermanent uint16 = 0x80 // NUD_PERMANENT
)

type ipv6NeighCandidate struct {
	ip           net.IP
	ipStr        string
	stateRank    int // 3=REACHABLE, 2=DELAY/PROBE/PERMANENT, 1=STALE
	hasCacheInfo bool
	confirmedAge uint32 // NDA_CACHEINFO.ndm_confirmed (ticks since last confirm, smaller = fresher)
	updatedAge   uint32 // NDA_CACHEINFO.ndm_updated (ticks since last update, smaller = fresher)
	orderIdx     int
}

func ipv6NeighStateRank(state uint16) int {
	switch {
	case (state & nudReachable) != 0:
		return 3
	case (state & (nudDelay | nudProbe | nudPermanent)) != 0:
		return 2
	case (state & nudStale) != 0:
		return 1
	default:
		return 0
	}
}

func ipv6NeighCandidateBetter(a, b ipv6NeighCandidate) bool {
	if a.stateRank != b.stateRank {
		return a.stateRank > b.stateRank
	}
	if a.hasCacheInfo && b.hasCacheInfo {
		if a.confirmedAge != b.confirmedAge {
			return a.confirmedAge < b.confirmedAge
		}
		if a.updatedAge != b.updatedAge {
			return a.updatedAge < b.updatedAge
		}
	} else if a.hasCacheInfo != b.hasCacheInfo {
		return a.hasCacheInfo
	}
	return a.orderIdx < b.orderIdx
}

func buildGetNeighIPv6DumpMsg(seq uint32) []byte {
	const ndmsgLen = 12
	total := rtnlMsgHdrLen + ndmsgLen
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], rtnlGetNeigh)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(rtnlFRequest|rtnlFDump))
	binary.LittleEndian.PutUint32(buf[8:12], seq)
	buf[16] = rtnlAfInet6 // ndm_family = AF_INET6
	return buf
}

func parseIPv6NeighDumpChunkCandidates(
	b []byte,
	allowedIfindexes map[int]bool,
	byMAC map[string]map[string]ipv6NeighCandidate,
	orderCounter *int,
) (bool, error) {
	const ndmsgLen = 12
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, errors.New("rtnl neigh dump: truncated nlmsghdr")
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, fmt.Errorf("rtnl neigh dump: bad nlmsg_len %d", msgLen)
		}
		msg := b[off : off+msgLen]
		adv := rtnlAlign(msgLen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}

		switch msgType {
		case rtnlMsgDone:
			return true, nil
		case rtnlMsgError:
			if len(msg) < rtnlMsgHdrLen+4 {
				return false, errors.New("rtnl neigh dump: truncated nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code != 0 {
				return false, fmt.Errorf("rtnl neigh dump errno %d", code)
			}
			continue
		case rtnlMsgNoop:
			continue
		}

		if msgType != rtnlNewNeigh || len(msg) < rtnlMsgHdrLen+ndmsgLen {
			continue
		}
		body := msg[rtnlMsgHdrLen:]
		if body[0] != rtnlAfInet6 {
			continue
		}
		ifidx := int(int32(binary.LittleEndian.Uint32(body[4:8])))
		if len(allowedIfindexes) > 0 && !allowedIfindexes[ifidx] {
			continue
		}
		state := binary.LittleEndian.Uint16(body[8:10])
		rank := ipv6NeighStateRank(state)
		if rank <= 0 {
			continue
		}

		var (
			ip           net.IP
			mac          string
			hasCacheInfo bool
			confirmedAge uint32
			updatedAge   uint32
		)
		attrs := body[ndmsgLen:]
		for aoff := 0; aoff < len(attrs); {
			arem := len(attrs) - aoff
			if arem < rtnlAttrHdr {
				break
			}
			alen := int(binary.LittleEndian.Uint16(attrs[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(attrs[aoff+2:aoff+4]) & 0x3fff
			if alen < rtnlAttrHdr || alen > arem {
				break
			}
			aval := attrs[aoff+4 : aoff+alen]
			switch {
			case atype == ndaDst && len(aval) == 16:
				ip = net.IP(append([]byte(nil), aval...))
			case atype == ndaLLAddr && len(aval) == 6:
				mac = strings.ToLower(net.HardwareAddr(aval).String())
			case atype == ndaCacheInfo && len(aval) >= 12:
				confirmedAge = binary.LittleEndian.Uint32(aval[0:4])
				updatedAge = binary.LittleEndian.Uint32(aval[8:12])
				hasCacheInfo = true
			}
			nadv := rtnlAlign(alen)
			if nadv > arem {
				break
			}
			aoff += nadv
		}

		if mac == "" || ip == nil || ip.To4() != nil ||
			ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		ipStr := ip.String()
		idxVal := 0
		if orderCounter != nil {
			idxVal = *orderCounter
			*orderCounter++
		}
		cand := ipv6NeighCandidate{
			ip:           ip,
			ipStr:        ipStr,
			stateRank:    rank,
			hasCacheInfo: hasCacheInfo,
			confirmedAge: confirmedAge,
			updatedAge:   updatedAge,
			orderIdx:     idxVal,
		}
		mMap := byMAC[mac]
		if mMap == nil {
			mMap = make(map[string]ipv6NeighCandidate, 4)
			byMAC[mac] = mMap
		}
		if prev, exists := mMap[ipStr]; !exists || ipv6NeighCandidateBetter(cand, prev) {
			if exists || len(mMap) < 4096 {
				mMap[ipStr] = cand
			}
		}
	}
	return false, nil
}

func rankAndCapIPv6Neighbors(byMAC map[string]map[string]ipv6NeighCandidate, maxPerMAC int) map[string][]net.IP {
	out := make(map[string][]net.IP, len(byMAC))
	for mac, mMap := range byMAC {
		if len(mMap) == 0 {
			continue
		}
		cands := make([]ipv6NeighCandidate, 0, len(mMap))
		for _, c := range mMap {
			cands = append(cands, c)
		}
		sort.Slice(cands, func(i, j int) bool {
			return ipv6NeighCandidateBetter(cands[i], cands[j])
		})
		limit := len(cands)
		if maxPerMAC > 0 && limit > maxPerMAC {
			limit = maxPerMAC
		}
		ips := make([]net.IP, 0, limit)
		for i := 0; i < limit; i++ {
			ips = append(ips, cands[i].ip)
		}
		out[mac] = ips
	}
	return out
}

// parseIPv6NeighDumpMsgs 纯字节流解析 RTM_NEWNEIGH dump 响应报文:
// 收集全部全局 IPv6 邻居后按状态优先级(REACHABLE > DELAY/PROBE/PERMANENT > STALE)与确认时间排序再截断前 16 条。
func parseIPv6NeighDumpMsgs(b []byte, allowedIfindexes map[int]bool) (map[string][]net.IP, bool, error) {
	allCands := make(map[string]map[string]ipv6NeighCandidate)
	orderCounter := 0
	done, err := parseIPv6NeighDumpChunkCandidates(b, allowedIfindexes, allCands, &orderCounter)
	return rankAndCapIPv6Neighbors(allCands, v6IPv6MaxAddrs), done, err
}

// acquireV6SyncLock 获取与 ./bin/v6_sync.sh 完全兼容的 <hncDir>/run/v6_sync.lock 目录锁(含 <lock>/pid 死进程回收),
// 杜绝 Go 原生 IPv6 u32 同步与 watchdog/事件脚本并发交错操作同一 prio 段。
var v6SyncLocalMu sync.Mutex

func acquireV6SyncLock(hncDir string) (func(), error) {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return func() {}, nil
	}
	v6SyncLocalMu.Lock()
	runDir := filepath.Join(hncDir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		v6SyncLocalMu.Unlock()
		return nil, err
	}
	lockDir := filepath.Join(runDir, "v6_sync.lock")
	pidPath := filepath.Join(lockDir, "pid")
	selfPID := os.Getpid()
	selfPIDStr := strconv.Itoa(selfPID)

	for round := 0; round < 120; round++ {
		if err := os.Mkdir(lockDir, 0o755); err == nil {
			_ = os.WriteFile(pidPath, []byte(selfPIDStr+"\n"), 0o644)
			var once sync.Once
			return func() {
				once.Do(func() {
					if b, rErr := os.ReadFile(pidPath); rErr == nil {
						if holder := strings.TrimSpace(string(b)); holder == "" || holder == selfPIDStr {
							_ = os.RemoveAll(lockDir)
						}
					} else {
						_ = os.RemoveAll(lockDir)
					}
					v6SyncLocalMu.Unlock()
				})
			}, nil
		}
		if b, rErr := os.ReadFile(pidPath); rErr == nil {
			if pid, pErr := strconv.Atoi(strings.TrimSpace(string(b))); pErr == nil && pid > 0 && !dpPidAlive(pid) {
				_ = os.RemoveAll(lockDir)
				continue
			}
		} else if st, sErr := os.Stat(lockDir); sErr == nil && time.Since(st.ModTime()) >= 5*time.Second {
			_ = os.RemoveAll(lockDir)
			continue
		}
		if st, sErr := os.Stat(lockDir); sErr == nil && time.Since(st.ModTime()) >= 60*time.Second {
			_ = os.RemoveAll(lockDir)
			continue
		}
		time.Sleep(25 * time.Millisecond)
	}
	v6SyncLocalMu.Unlock()
	return nil, errors.New("v6_sync.lock busy timeout")
}

// DumpNativeIPv6Neighbors 通过原生 AF_NETLINK RTM_GETNEIGH 读取指定下游接口上的活跃全局 IPv6 邻居映射。
func DumpNativeIPv6Neighbors(allowedIfindexes map[int]bool) (map[string][]net.IP, error) {
	return dumpNativeIPv6NeighborsOS(allowedIfindexes)
}

// NativeSyncIPv6FiltersWithDirV6 在持有 run/v6_sync.lock 互斥锁保护下同步受控设备的 128-bit IPv6 u32 过滤器。
func NativeSyncIPv6FiltersWithDirV6(hncDir string, downIfindexes []int, ifbIfindex int, midByMAC map[string]int, upLimitedMAC map[string]bool) (int, error) {
	unlock, err := acquireV6SyncLock(hncDir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return NativeSyncIPv6FiltersV6(downIfindexes, ifbIfindex, midByMAC, upLimitedMAC)
}

// NativeSyncIPv6FiltersV6 在所有并管下游接口与上行 ifb0 上原生同步受控设备的 128-bit IPv6 u32 过滤器。
func NativeSyncIPv6FiltersV6(downIfindexes []int, ifbIfindex int, midByMAC map[string]int, upLimitedMAC map[string]bool) (int, error) {
	globalV6Subtrees.v6NeighSyncs.Add(1)
	if len(downIfindexes) == 0 || len(midByMAC) == 0 {
		return 0, nil
	}
	allow := make(map[int]bool, len(downIfindexes))
	for _, idx := range downIfindexes {
		if idx > 0 {
			allow[idx] = true
		}
	}
	neighByMAC, err := DumpNativeIPv6Neighbors(allow)
	if err != nil {
		return 0, err
	}

	fd, err := openRTNetlinkSocket()
	if err != nil {
		return 0, err
	}
	defer closeRTNetlinkSocket(fd)

	totalSynced := 0
	for mac, mid := range midByMAC {
		ips := neighByMAC[strings.ToLower(mac)]
		if len(ips) == 0 || mid < 1 || mid > 99 {
			continue
		}
		minor, mErr := htbClassMinorForMid(mid)
		if mErr != nil {
			continue
		}
		clsHandle := rtnlHtbRootMaj | uint32(minor)
		prio := uint16(200 + mid)

		for _, downIdx := range downIfindexes {
			delSeq := rtnlNextSeq()
			_ = nlBatchSendAckFn(fd, buildDelFilterMsg(delSeq, downIdx, rtnlHtbRootMaj, 0, prio, rtnlEthPIPv6, ""), delSeq)
			for _, ip6 := range ips {
				seq := rtnlNextSeq()
				msg, bErr := BuildU32IPv6FilterMsg(seq, downIdx, rtnlHtbRootMaj, prio, ip6, false, clsHandle)
				if bErr == nil {
					if nlBatchSendAckFn(fd, msg, seq) == nil {
						totalSynced++
					}
				}
			}
		}
		if ifbIfindex > 0 && upLimitedMAC[strings.ToLower(mac)] {
			delSeq := rtnlNextSeq()
			_ = nlBatchSendAckFn(fd, buildDelFilterMsg(delSeq, ifbIfindex, rtnlHtbRootMaj, 0, prio, rtnlEthPIPv6, ""), delSeq)
			for _, ip6 := range ips {
				seq := rtnlNextSeq()
				msg, bErr := BuildU32IPv6FilterMsg(seq, ifbIfindex, rtnlHtbRootMaj, prio, ip6, true, clsHandle)
				if bErr == nil {
					_ = nlBatchSendAckFn(fd, msg, seq)
				}
			}
		}
	}
	return totalSynced, nil
}

// ── 6. 开机冷启全量原生恢复 NativeFullRestoreV6 (<25ms 替代 18+ 次 shell 拉起) ──

func sendNetlinkBatchBestEffort(fd int, msgs [][]byte) (sent int, hardErr error) {
	return nlSendBatchWithCompatFallback(fd, msgs, true)
}

// CurrentDynamicQoSRatios 从 autorate 与黑匣子实时读取当前 RTT/抖动并平滑计算最新三档比例。
func (s *server) CurrentDynamicQoSRatios() QoSDynamicRatios {
	var jitterMs, deltaRTTMs float64
	if s != nil && s.autorate != nil {
		ar := s.autorate.Snapshot()
		if ar.DeltaRTTMs > 0 {
			deltaRTTMs = ar.DeltaRTTMs
		}
	}
	if bbJitter := globalJitterBlackbox.LatestJitterMs(); bbJitter > jitterMs {
		jitterMs = bbJitter
	}
	ratios, _ := globalV6Subtrees.SmoothStepDynamicQoS(jitterMs, deltaRTTMs)
	return ratios
}

var (
	v6ResolveIfaceIndexFn  = nlIfaceIndexByName
	v6DumpIPv6NeighborsFn  = DumpNativeIPv6Neighbors
	v6EnsureBaseHooksFn    = ensureFirewallBaseHooksLinked
	v6ResolveRestoreBinFn  = resolveIptablesRestoreBin
	v6TriggerAppQoSFn      = defaultTriggerAppQoSScript
	v6AppQoSSyncInFlight   atomic.Bool
)

func subtreeDeviceNeedsMark(hncDir, mac string, mid int, dm map[string]any) bool {
	if mid < 1 || mid > 99 {
		return false
	}
	if anyToRuleBool(dm["limit_enabled"]) || anyToRuleBool(dm["delay_enabled"]) ||
		anyToRuleBool(dm["sqm_enabled"]) || anyToRuleBool(dm["app_qos"]) {
		return true
	}
	for _, f := range []string{"down_mbps", "up_mbps", "delay_ms", "jitter_ms", "loss_pct"} {
		if numFieldGT0(dm[f]) {
			return true
		}
	}
	return deviceHasSecondaryQdiscOwner(hncDir, "", mac, mid, dm)
}

// BuildFirewallPayloads 从 rules.json 快照(root)与在线 IPv4 映射(liveIPv4)全量构造设备级
// 双栈 iptables-restore / ip6tables-restore --noflush 载荷(:HNC_MARK - [0:0] 与 :HNC_CTRL - [0:0])。
func BuildFirewallPayloads(hncDir string, root map[string]any, liveIPv4 map[string]string, rejectDropFallback bool) ([]byte, []byte) {
	if root == nil && hncDir != "" {
		root, _ = rulesStore.ReadAll(hncDir)
	}
	if liveIPv4 == nil && hncDir != "" {
		liveIPv4 = readLiveDeviceIPv4Map(hncDir)
	}

	type devEntry struct {
		mac  string
		ipv4 string
		mid  int
	}
	markedByMAC := make(map[string]devEntry)
	devIPByMAC := make(map[string]string)
	if devs, ok := root["devices"].(map[string]any); ok {
		for rawMAC, rawObj := range devs {
			mac := strings.ToLower(strings.TrimSpace(rawMAC))
			dm, ok := rawObj.(map[string]any)
			if !ok || !macRE.MatchString(mac) {
				continue
			}
			ip := strings.TrimSpace(liveIPv4[mac])
			if !validStrictIPv4(ip) {
				if sIP := strings.TrimSpace(anyToRuleString(dm["ip"])); validStrictIPv4(sIP) {
					ip = sIP
				} else {
					ip = ""
				}
			}
			if ip != "" {
				devIPByMAC[mac] = ip
			}
			mid := anyToRuleInt(dm["mark_id"])
			if subtreeDeviceNeedsMark(hncDir, mac, mid, dm) {
				markedByMAC[mac] = devEntry{mac: mac, ipv4: ip, mid: mid}
			}
		}
	}

	blockedByMAC := make(map[string]string)
	addBlocked := func(raw string) {
		mac := strings.ToLower(strings.TrimSpace(raw))
		if !macRE.MatchString(mac) {
			return
		}
		ip := strings.TrimSpace(liveIPv4[mac])
		if !validStrictIPv4(ip) {
			ip = devIPByMAC[mac]
		}
		blockedByMAC[mac] = ip
	}
	switch bl := root["blacklist"].(type) {
	case []any:
		for _, v := range bl {
			addBlocked(anyToRuleString(v))
		}
	case []string:
		for _, v := range bl {
			addBlocked(v)
		}
	}

	markedList := make([]devEntry, 0, len(markedByMAC))
	for _, d := range markedByMAC {
		markedList = append(markedList, d)
	}
	sort.Slice(markedList, func(i, j int) bool { return markedList[i].mac < markedList[j].mac })

	blockedList := make([]devEntry, 0, len(blockedByMAC))
	for mac, ip := range blockedByMAC {
		blockedList = append(blockedList, devEntry{mac: mac, ipv4: ip})
	}
	sort.Slice(blockedList, func(i, j int) bool { return blockedList[i].mac < blockedList[j].mac })

	var v4, v6 bytes.Buffer
	v4.WriteString("*mangle\n:HNC_MARK - [0:0]\n")
	v6.WriteString("*mangle\n:HNC_MARK - [0:0]\n")
	for _, d := range markedList {
		markVal, markMask := readDeviceMarkSpec(hncDir, d.mid)
		xmark := fmt.Sprintf("0x%08x/0x%08x", markVal, markMask)
		zeroMatch := fmt.Sprintf("0x0/0x%08x", markMask)
		if d.ipv4 != "" {
			fmt.Fprintf(&v4, "-A HNC_MARK -s %s/32 -m mac --mac-source %s -j MARK --set-xmark %s\n", d.ipv4, d.mac, xmark)
		}
		fmt.Fprintf(&v4, "-A HNC_MARK -m mac --mac-source %s -m mark --mark %s -j MARK --set-xmark %s\n", d.mac, zeroMatch, xmark)
		if d.ipv4 != "" {
			fmt.Fprintf(&v4, "-A HNC_MARK -d %s/32 -j MARK --set-xmark %s\n", d.ipv4, xmark)
		}
		fmt.Fprintf(&v6, "-A HNC_MARK -m mac --mac-source %s -m mark --mark %s -j MARK --set-xmark %s\n", d.mac, zeroMatch, xmark)
	}
	v4.WriteString("COMMIT\n")
	v6.WriteString("COMMIT\n")

	v4.WriteString("*filter\n:HNC_CTRL - [0:0]\n")
	v6.WriteString("*filter\n:HNC_CTRL - [0:0]\n")
	for _, b := range blockedList {
		if rejectDropFallback {
			fmt.Fprintf(&v4, "-A HNC_CTRL -m mac --mac-source %s -p tcp -j DROP\n", b.mac)
			fmt.Fprintf(&v6, "-A HNC_CTRL -m mac --mac-source %s -p tcp -j DROP\n", b.mac)
		} else {
			fmt.Fprintf(&v4, "-A HNC_CTRL -m mac --mac-source %s -p tcp -j REJECT --reject-with tcp-reset\n", b.mac)
			fmt.Fprintf(&v6, "-A HNC_CTRL -m mac --mac-source %s -p tcp -j REJECT --reject-with tcp-reset\n", b.mac)
		}
		fmt.Fprintf(&v4, "-A HNC_CTRL -m mac --mac-source %s -p udp --dport 443 -j DROP\n", b.mac)
		fmt.Fprintf(&v4, "-A HNC_CTRL -m mac --mac-source %s -j DROP\n", b.mac)
		if b.ipv4 != "" {
			fmt.Fprintf(&v4, "-A HNC_CTRL -s %s/32 -j DROP\n", b.ipv4)
			fmt.Fprintf(&v4, "-A HNC_CTRL -d %s/32 -j DROP\n", b.ipv4)
		}
		fmt.Fprintf(&v6, "-A HNC_CTRL -m mac --mac-source %s -p udp --dport 443 -j DROP\n", b.mac)
		fmt.Fprintf(&v6, "-A HNC_CTRL -m mac --mac-source %s -j DROP\n", b.mac)
	}
	v4.WriteString("COMMIT\n")
	v6.WriteString("COMMIT\n")

	return v4.Bytes(), v6.Bytes()
}

func classifyAppQoSTierForPlan(category string) int {
	c := strings.ToLower(strings.TrimSpace(category))
	switch {
	case c == "":
		return 2
	case strings.HasPrefix(c, "game"), strings.Contains(c, "voip"), c == "call", strings.HasPrefix(c, "sdk-tencent-game"):
		return 1
	case c == "download", c == "cloud", c == "update", strings.HasPrefix(c, "p2p"),
		c == "system", strings.HasPrefix(c, "system-"), strings.HasPrefix(c, "system_"),
		strings.Contains(c, "telemetry"), c == "ads", c == "ad-sdk", strings.HasPrefix(c, "sdk"):
		return 3
	default:
		return 2
	}
}

func writeNativeRestoreAppQoSPlan(hncDir, iface string, root map[string]any, liveIPv4 map[string]string) {
	iface = strings.TrimSpace(iface)
	if hncDir == "" || iface == "" || !ifaceNameOK(iface) {
		return
	}
	type qosDev struct {
		mid int
		mac string
		ip  string
	}
	var ds []qosDev
	seenMid := map[int]bool{}
	if devs, ok := root["devices"].(map[string]any); ok {
		for rawMAC, rawObj := range devs {
			mac := strings.ToLower(strings.TrimSpace(rawMAC))
			dm, ok := rawObj.(map[string]any)
			if !ok || !macRE.MatchString(mac) || !anyToRuleBool(dm["app_qos"]) || deviceHasDelayOwner(dm) {
				continue
			}
			mid := anyToRuleInt(dm["mark_id"])
			if mid < 1 || mid > 99 || seenMid[mid] {
				continue
			}
			seenMid[mid] = true
			ip := strings.TrimSpace(liveIPv4[mac])
			if !validStrictIPv4(ip) {
				if sIP := strings.TrimSpace(anyToRuleString(dm["ip"])); validStrictIPv4(sIP) {
					ip = sIP
				} else {
					ip = ""
				}
			}
			ds = append(ds, qosDev{mid: mid, mac: mac, ip: ip})
		}
	}
	if len(ds) == 0 {
		return
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].mid < ds[j].mid })

	var sb strings.Builder
	fmt.Fprintf(&sb, "iface %s\n", iface)
	for _, d := range ds {
		if d.ip != "" {
			fmt.Fprintf(&sb, "dev %d %s %s\n", d.mid, d.mac, d.ip)
		} else {
			fmt.Fprintf(&sb, "dev %d %s\n", d.mid, d.mac)
		}
	}

	if ipMapRaw, err := os.ReadFile(filepath.Join(hncDir, "run", "ip_app_map.json")); err == nil {
		var doc struct {
			Entries []struct {
				IP       string `json:"ip"`
				Category string `json:"category"`
			} `json:"entries"`
		}
		if json.Unmarshal(ipMapRaw, &doc) == nil {
			type ipTier struct {
				ip   string
				tier int
			}
			var v4s, v6s []ipTier
			seen := map[string]bool{}
			for _, e := range doc.Entries {
				tier := classifyAppQoSTierForPlan(e.Category)
				if tier == 2 {
					continue
				}
				nip := net.ParseIP(strings.TrimSpace(e.IP))
				if nip == nil || nip.IsLoopback() || nip.IsLinkLocalUnicast() || nip.IsMulticast() || nip.IsUnspecified() {
					continue
				}
				canon := nip.String()
				if seen[canon] {
					continue
				}
				seen[canon] = true
				if nip.To4() != nil {
					v4s = append(v4s, ipTier{ip: canon, tier: tier})
				} else {
					v6s = append(v6s, ipTier{ip: canon, tier: tier})
				}
			}
			sort.Slice(v4s, func(i, j int) bool { return v4s[i].ip < v4s[j].ip })
			sort.Slice(v6s, func(i, j int) bool { return v6s[i].ip < v6s[j].ip })
			if len(v4s) > 1000 {
				v4s = v4s[:1000]
			}
			if len(v6s) > 1000 {
				v6s = v6s[:1000]
			}
			for _, it := range v4s {
				fmt.Fprintf(&sb, "ip %d %s\n", it.tier, it.ip)
			}
			for _, it := range v6s {
				fmt.Fprintf(&sb, "ip %d %s\n", it.tier, it.ip)
			}
		}
	}
	_ = discoverWriteAtomic(filepath.Join(hncDir, "run", "app_qos.plan"), []byte(sb.String()))
}

func defaultTriggerAppQoSScript(hncDir string) {
	if hncDir == "" {
		return
	}
	scriptPath := filepath.Join(hncDir, "bin", "apply_app_qos.sh")
	if st, err := os.Stat(scriptPath); err != nil || st.IsDir() {
		return
	}
	if !v6AppQoSSyncInFlight.CompareAndSwap(false, true) {
		return
	}
	go func(dir string) {
		defer v6AppQoSSyncInFlight.Store(false)
		_, _ = runBin(dir, "apply_app_qos.sh")
	}(hncDir)
}

// NativeFullRestoreV6 执行全量 Go 原生数据面冷启/热恢复:
//   - 多下游接口自动发现 + HTB 根队列 + 1:fffe 2.5Gbps 局域网互传直通类;
//   - 全量设备下行/上行 HTB 限速类 + 双栈 HNC_MARK / HNC_CTRL 原子提交;
//   - 单应用限速 1:9001+ 二级子树 + 双栈 CONNMARK / QUIC 降级规则;
//   - 三档动态延迟联动应用 QoS 1:a0XX 二级子树;
//   - 原生 IPv6 邻居探测与 128-bit u32 过滤器同步。
func (s *server) NativeFullRestoreV6() (V6NativeRestoreReport, error) {
	t0 := time.Now()
	globalV6Subtrees.fullRestores.Add(1)
	rep := V6NativeRestoreReport{
		RestoredAtMs: t0.UnixMilli(),
		QoSRatios:    s.CurrentDynamicQoSRatios(),
	}
	if s == nil || s.hncDir == "" {
		return rep, errors.New("NativeFullRestoreV6: nil server or empty hncDir")
	}

	unlock, lockErr := acquireNativeDataplaneLock(s.hncDir, "v6_full_restore")
	if lockErr != nil {
		return rep, lockErr
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()

	// 1. 多口发现与 1:fffe 直通类就绪
	miSnap, miErr := s.ReconcileMultiDownstreamV6()
	if miErr != nil {
		rep.Warnings = append(rep.Warnings, miErr.Error())
	}
	var downIfindexes []int
	for _, ds := range miSnap.ManagedDownstreams {
		if ds.ShapeEnabled && ds.Ifindex > 0 {
			rep.DownstreamIfaces = append(rep.DownstreamIfaces, ds.Name)
			downIfindexes = append(downIfindexes, ds.Ifindex)
		}
	}
	ifbIdx, _ := v6ResolveIfaceIndexFn("ifb0")

	// 2. 读取 rules.json 与在线 IP 表
	root, err := rulesStore.ReadAll(s.hncDir)
	if err != nil {
		return rep, err
	}
	liveIPv4 := readLiveDeviceIPv4Map(s.hncDir)

	type devRestoreSpec struct {
		mac      string
		ipv4     string
		mid      int
		dnBps    uint64
		upBps    uint64
		appQoSOn bool
	}
	var devSpecs []devRestoreSpec
	midByMAC := make(map[string]int)
	upLimitedMAC := make(map[string]bool)

	if devs, ok := root["devices"].(map[string]any); ok {
		for rawMAC, rawObj := range devs {
			mac := strings.ToLower(strings.TrimSpace(rawMAC))
			dm, ok := rawObj.(map[string]any)
			if !ok || !macRE.MatchString(mac) {
				continue
			}
			mid := anyToRuleInt(dm["mark_id"])
			if mid < 1 || mid > 99 {
				continue
			}
			ip := liveIPv4[mac]
			if ip == "" {
				if sIP := strings.TrimSpace(anyToRuleString(dm["ip"])); validStrictIPv4(sIP) {
					ip = sIP
				}
			}
			if ip != "" {
				liveIPv4[mac] = ip
			}
			var dnBps, upBps uint64
			if anyToRuleBool(dm["limit_enabled"]) {
				dnBps, _ = mbpsStrToBytesPerSec(anyToRuleString(dm["down_mbps"]))
				upBps, _ = mbpsStrToBytesPerSec(anyToRuleString(dm["up_mbps"]))
			}
			appQoS := anyToRuleBool(dm["app_qos"]) && !deviceHasDelayOwner(dm)
			hasAppLim := deviceHasAppLimitsForMAC(s.hncDir, "", mac, mid)
			if dnBps == 0 && upBps == 0 && !appQoS && !hasAppLim {
				continue
			}
			midByMAC[mac] = mid
			if upBps > 0 {
				upLimitedMAC[mac] = true
			}
			devSpecs = append(devSpecs, devRestoreSpec{
				mac:      mac,
				ipv4:     ip,
				mid:      mid,
				dnBps:    dnBps,
				upBps:    upBps,
				appQoSOn: appQoS,
			})
		}
	}
	sort.Slice(devSpecs, func(i, j int) bool { return devSpecs[i].mac < devSpecs[j].mac })

	assignments := s.PlanAppLimitSlotAssignments(midByMAC)
	byDevAsg := make(map[int][]V6AppLimitSlotAssignment)
	for _, asg := range assignments {
		byDevAsg[asg.Mid] = append(byDevAsg[asg.Mid], asg)
	}
	rep.AppLimitClasses = len(assignments)

	expActive, expMark, expBgCeilKbps := resolveActiveVectorExpressParams(s, s.hncDir)

	// 3. 若处于原生数据面环境且存在活跃下游口, 下发全部 HTB 设备类、二级子树与双栈防火墙
	if useNativeDataplane(s.hncDir) && len(downIfindexes) > 0 {
		allowIfidx := make(map[int]bool, len(downIfindexes))
		for _, idx := range downIfindexes {
			if idx > 0 {
				allowIfidx[idx] = true
			}
		}
		var devIPv6ByMAC map[string][]string
		if neighByMAC, nErr := v6DumpIPv6NeighborsFn(allowIfidx); nErr == nil && len(neighByMAC) > 0 {
			devIPv6ByMAC = make(map[string][]string, len(neighByMAC))
			for mac, ips := range neighByMAC {
				macKey := strings.ToLower(strings.TrimSpace(mac))
				for _, ip6 := range ips {
					if ip6 != nil && ip6.To4() == nil {
						devIPv6ByMAC[macKey] = append(devIPv6ByMAC[macKey], ip6.String())
					}
				}
			}
		}

		// 同步设备级双栈 HNC_MARK / HNC_CTRL 防火墙规则
		if v6EnsureBaseHooksFn() {
			v4DevFW, v6DevFW := BuildFirewallPayloads(s.hncDir, root, liveIPv4, false)
			if v4Bin := v6ResolveRestoreBinFn("iptables-restore"); v4Bin != "" {
				mangleOK, filterOK, anyOK, _ := pipeRestoreTablesIsolated(v4Bin, v4DevFW)
				if !anyOK {
					v4Drop, v6Drop := BuildFirewallPayloads(s.hncDir, root, liveIPv4, true)
					if mOK, fOK, dOK, _ := pipeRestoreTablesIsolated(v4Bin, v4Drop); mOK || fOK || dOK {
						anyOK = true
						v6DevFW = v6Drop
					}
				} else if mangleOK || filterOK {
					anyOK = true
				}
				if anyOK {
					rep.FirewallUpdated = true
					iptBin := v6ResolveRestoreBinFn("iptables")
					for _, ds := range devSpecs {
						if validStrictIPv4(ds.ipv4) {
							ensureNativeIPv4StatsRule(iptBin, ds.ipv4)
						}
					}
				}
			}
			if v6Bin := v6ResolveRestoreBinFn("ip6tables-restore"); v6Bin != "" {
				if mOK, fOK, v6OK, _ := pipeRestoreTablesIsolated(v6Bin, v6DevFW); mOK || fOK || v6OK {
					rep.FirewallUpdated = true
				} else {
					_, v6Drop := BuildFirewallPayloads(s.hncDir, root, liveIPv4, true)
					if m2, f2, d2, _ := pipeRestoreTablesIsolated(v6Bin, v6Drop); m2 || f2 || d2 {
						rep.FirewallUpdated = true
					}
				}
			}
		}

		fd, sErr := openRTNetlinkSocket()
		if sErr != nil {
			rep.Warnings = append(rep.Warnings, sErr.Error())
			for _, ds := range devSpecs {
				if ds.upBps > 0 && ifbIdx <= 0 {
					markVal, markMask := readDeviceMarkSpec(s.hncDir, ds.mid)
					for _, downName := range rep.DownstreamIfaces {
						_ = applyNativeIngressPolice(s.hncDir, downName, ds.mid, ds.mac, ds.ipv4, ds.upBps, markVal, markMask)
					}
				}
				if ds.appQoSOn {
					rep.AppQoSDevices++
				}
				rep.DevicesRestored++
			}
		} else {
			defer closeRTNetlinkSocket(fd)
			tick := readPschedTickInUsec()

			for _, ds := range devSpecs {
				minor, mErr := htbClassMinorForMid(ds.mid)
				if mErr != nil {
					continue
				}
				markVal, markMask := readDeviceMarkSpec(s.hncDir, ds.mid)
				effDn := ds.dnBps
				if effDn == 0 {
					effDn = DefaultHTBRootRateBps
				}
				for _, downIdx := range downIfindexes {
					_ = nlUpsertDeviceHTB(downIdx, minor, effDn, effDn, 0, 0, 0, markVal, markMask, ds.ipv4, false)
					if len(byDevAsg[ds.mid]) > 0 {
						if batch, bErr := BuildAppLimitSubtreeNetlinkBatch(downIdx, ds.mid, effDn, effDn, markVal, markMask, byDevAsg[ds.mid], ds.appQoSOn, tick); bErr == nil {
							nSent, _ := sendNetlinkBatchBestEffort(fd, batch)
							rep.NetlinkMessages += nSent
							globalV6Subtrees.appLimitApplies.Add(1)
						}
					}
					if ds.appQoSOn {
						if batch, bErr := BuildAppQoSSubtreeNetlinkBatch(downIdx, ds.mid, effDn, effDn, markVal, markMask, rep.QoSRatios, tick); bErr == nil {
							nSent, _ := sendNetlinkBatchBestEffort(fd, batch)
							rep.NetlinkMessages += nSent
							globalV6Subtrees.appQoSApplies.Add(1)
						}
					}
				}
				if ds.upBps > 0 && ifbIdx > 0 {
					_ = nlUpsertDeviceHTB(ifbIdx, minor, ds.upBps, ds.upBps, 0, 0, 0, markVal, markMask, ds.ipv4, true)
				} else if ds.upBps > 0 {
					// GKI 6.1/6.6/6.12 无 CONFIG_IFB 场景: 全量恢复时补齐双栈入口 ingress police 上行限速
					for _, downName := range rep.DownstreamIfaces {
						if pErr := applyNativeIngressPolice(s.hncDir, downName, ds.mid, ds.mac, ds.ipv4, ds.upBps, markVal, markMask); pErr != nil {
							upKbit := (ds.upBps * 8) / 1000
							if upKbit < 64 {
								upKbit = 64
							}
							if _, stErr := os.Stat(filepath.Join(s.hncDir, "bin", "tc_manager.sh")); stErr == nil {
								_, _ = runBin(s.hncDir, "tc_manager.sh", "set_uplink_police", downName, classIDStringForMid(ds.mid), strconv.FormatUint(upKbit, 10)+"kbit", ds.ipv4, ds.mac)
							} else {
								rep.Warnings = append(rep.Warnings, fmt.Sprintf("ingress police (%s/%s): %v", downName, ds.mac, pErr))
							}
						}
					}
				}
				if ds.appQoSOn {
					rep.AppQoSDevices++
				}
				rep.DevicesRestored++
			}

			// 若 Vector Express 活跃, 对全部并管下游口与 ifb0 重放 1:8010 特快通道
			if expActive {
				expMask := resolveOrthogonalFilterMask(expMark, DefaultAppQoSMarkMask)
				bgBps := kbpsToBytesPerSec(expBgCeilKbps)
				for _, downIdx := range downIfindexes {
					var eb [][]byte
					eb = append(eb, buildVectorExpressLegacyCleanupBatch(s.hncDir, downIdx, false, expMark, expMask)...)
					eb = append(eb, buildVectorExpressUpsertBatch(downIdx, false, DefaultHTBRootRateBps, bgBps, expMark, expMask, tick)...)
					nSent, _ := sendNetlinkBatchBestEffort(fd, eb)
					rep.NetlinkMessages += nSent
				}
				if ifbIdx > 0 {
					var ub [][]byte
					ub = append(ub, buildVectorExpressLegacyCleanupBatch(s.hncDir, ifbIdx, true, expMark, expMask)...)
					ub = append(ub, buildVectorExpressUpsertBatch(ifbIdx, true, DefaultHTBRootRateBps, 0, expMark, expMask, tick)...)
					nSent, _ := sendNetlinkBatchBestEffort(fd, ub)
					rep.NetlinkMessages += nSent
				}
			}
		}

		// 同步应用限速双栈防火墙链及顶层挂载跳转 (分表容错提交 + 缺 REJECT 自动降级 -j DROP, 严防连坐回滚 *mangle 打标)
		if len(assignments) > 0 {
			v4App, v6App := BuildAppLimitFirewallPayloads(assignments, liveIPv4, devIPv6ByMAC)
			v4Restored := false
			if v4Bin := v6ResolveRestoreBinFn("iptables-restore"); v4Bin != "" {
				if mangleOK, _, anyOK, _ := pipeRestoreTablesIsolated(v4Bin, v4App); mangleOK || anyOK {
					rep.FirewallUpdated = true
					v4Restored = true
				}
			}
			v6Restored := false
			if v6Bin := v6ResolveRestoreBinFn("ip6tables-restore"); v6Bin != "" {
				if mangleOK, _, anyOK, _ := pipeRestoreTablesIsolated(v6Bin, v6App); mangleOK || anyOK {
					rep.FirewallUpdated = true
					v6Restored = true
				}
			}
			if v4Restored || v6ResolveRestoreBinFn("iptables-restore") == "" {
				ensureAppLimitTopHooksOnBin(v6ResolveRestoreBinFn("iptables"))
			}
			if v6Restored || v6ResolveRestoreBinFn("ip6tables-restore") == "" {
				ensureAppLimitTopHooksOnBin(v6ResolveRestoreBinFn("ip6tables"))
			}
		}

		// 同步原生 IPv6 邻居过滤器 (持 run/v6_sync.lock 防与脚本竞态)
		if synced, nErr := NativeSyncIPv6FiltersWithDirV6(s.hncDir, downIfindexes, ifbIdx, midByMAC, upLimitedMAC); nErr == nil {
			rep.IPv6AddrsSynced = synced
		}
	} else {
		for _, ds := range devSpecs {
			if ds.appQoSOn {
				rep.AppQoSDevices++
			}
			rep.DevicesRestored++
		}
	}

	locked = false
	unlock()

	if rep.AppQoSDevices > 0 && useNativeDataplane(s.hncDir) && len(rep.DownstreamIfaces) > 0 {
		_ = os.MkdirAll(filepath.Join(s.hncDir, "run"), 0o755)
		_ = os.WriteFile(filepath.Join(s.hncDir, "run", "app_limit.dirty"), nil, 0o644)
		writeNativeRestoreAppQoSPlan(s.hncDir, rep.DownstreamIfaces[0], root, liveIPv4)
		v6TriggerAppQoSFn(s.hncDir)
	}

	if expActive && useNativeDataplane(s.hncDir) {
		replayVectorExpressIfActive(s, s.hncDir)
	}

	rep.DurationMs = math.Round(float64(time.Since(t0).Microseconds())/10.0) / 100.0
	globalV6Subtrees.mu.Lock()
	globalV6Subtrees.lastRestore = rep
	globalV6Subtrees.mu.Unlock()

	// 落盘轻量运行态摘要供诊断页查阅
	if b, mErr := json.Marshal(rep); mErr == nil {
		_ = os.MkdirAll(filepath.Join(s.hncDir, "run"), 0o755)
		_ = discoverWriteAtomic(filepath.Join(s.hncDir, "run", "v6_native_restore.json"), append(b, '\n'))
	}
	return rep, nil
}

func runSubtreeIptCmd(iptBin string, args ...string) (string, error) {
	return runIptWithWaitFallback(iptBin, args...)
}

func findIptLastChainRuleLine(listOut, saveOut string, targets ...string) int {
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}
	lastMatch := 0
	for _, rawLn := range strings.Split(listOut, "\n") {
		fs := strings.Fields(strings.TrimSpace(rawLn))
		if len(fs) < 2 {
			continue
		}
		n, err := strconv.Atoi(fs[0])
		if err != nil || n <= 0 {
			continue
		}
		if want[fs[1]] {
			lastMatch = n
		}
	}
	if lastMatch > 0 || strings.TrimSpace(saveOut) == "" {
		return lastMatch
	}
	ruleIdx := 0
	for _, rawLn := range strings.Split(saveOut, "\n") {
		fs := strings.Fields(strings.TrimSpace(rawLn))
		if len(fs) < 4 || fs[0] != "-A" {
			continue
		}
		ruleIdx++
		for i := 2; i+1 < len(fs); i++ {
			if (fs[i] == "-j" || fs[i] == "-g") && want[fs[i+1]] {
				lastMatch = ruleIdx
			}
		}
	}
	return lastMatch
}

func findIptFirstChainRuleLine(listOut, saveOut, target string) int {
	for _, rawLn := range strings.Split(listOut, "\n") {
		fs := strings.Fields(strings.TrimSpace(rawLn))
		if len(fs) < 2 {
			continue
		}
		n, err := strconv.Atoi(fs[0])
		if err != nil || n <= 0 {
			continue
		}
		if fs[1] == target {
			return n
		}
	}
	if strings.TrimSpace(saveOut) == "" {
		return 0
	}
	ruleIdx := 0
	for _, rawLn := range strings.Split(saveOut, "\n") {
		fs := strings.Fields(strings.TrimSpace(rawLn))
		if len(fs) < 4 || fs[0] != "-A" {
			continue
		}
		ruleIdx++
		for i := 2; i+1 < len(fs); i++ {
			if (fs[i] == "-j" || fs[i] == "-g") && fs[i+1] == target {
				return ruleIdx
			}
		}
	}
	return 0
}

// ensureAppLimitTopHooksOnBin 幂等确保单应用限速三条顶层跳转链就绪:
//   - mangle/FORWARD -> HNC_APP_LIMIT_UP;
//   - filter/FORWARD -> HNC_QUIC_APPLIM;
//   - mangle/POSTROUTING -> HNC_APP_LIMIT_DOWN (严格位于 HNC_SAVE 之前, 防止尾部 HNC_EGRESS_FIX 覆盖前漏存 CONNMARK)。
func ensureAppLimitTopHooksOnBin(iptBin string) {
	iptBin = strings.TrimSpace(iptBin)
	if iptBin == "" {
		return
	}
	ensureChainExists := func(tbl, chain string) {
		if _, err := runSubtreeIptCmd(iptBin, "-t", tbl, "-L", chain, "-n"); err != nil {
			_, _ = runSubtreeIptCmd(iptBin, "-t", tbl, "-N", chain)
		}
	}

	// 1. mangle/FORWARD -> HNC_APP_LIMIT_UP
	if _, err := runSubtreeIptCmd(iptBin, "-t", "mangle", "-C", "FORWARD", "-j", "HNC_APP_LIMIT_UP"); err != nil {
		ensureChainExists("mangle", "HNC_APP_LIMIT_UP")
		listOut, _ := runSubtreeIptCmd(iptBin, "-t", "mangle", "-L", "FORWARD", "-n", "--line-numbers")
		saveOut := ""
		if findIptLastChainRuleLine(listOut, "", "HNC_STATS", "HNC_MARK") == 0 {
			saveOut, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-S", "FORWARD")
		}
		if anchorLn := findIptLastChainRuleLine(listOut, saveOut, "HNC_STATS", "HNC_MARK"); anchorLn > 0 {
			if _, iErr := runSubtreeIptCmd(iptBin, "-t", "mangle", "-I", "FORWARD", strconv.Itoa(anchorLn+1), "-j", "HNC_APP_LIMIT_UP"); iErr != nil {
				_, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-A", "FORWARD", "-j", "HNC_APP_LIMIT_UP")
			}
		} else {
			_, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-A", "FORWARD", "-j", "HNC_APP_LIMIT_UP")
		}
	}

	// 2. filter/FORWARD -> HNC_QUIC_APPLIM
	if _, err := runSubtreeIptCmd(iptBin, "-t", "filter", "-C", "FORWARD", "-j", "HNC_QUIC_APPLIM"); err != nil {
		ensureChainExists("filter", "HNC_QUIC_APPLIM")
		if _, iErr := runSubtreeIptCmd(iptBin, "-t", "filter", "-I", "FORWARD", "1", "-j", "HNC_QUIC_APPLIM"); iErr != nil {
			_, _ = runSubtreeIptCmd(iptBin, "-t", "filter", "-A", "FORWARD", "-j", "HNC_QUIC_APPLIM")
		}
	}

	// 3. mangle/POSTROUTING -> HNC_APP_LIMIT_DOWN (严格位于 HNC_SAVE 之前!)
	locatePostLines := func() (int, int) {
		lOut, _ := runSubtreeIptCmd(iptBin, "-t", "mangle", "-L", "POSTROUTING", "-n", "--line-numbers")
		sLn := findIptFirstChainRuleLine(lOut, "", "HNC_SAVE")
		dLn := findIptFirstChainRuleLine(lOut, "", "HNC_APP_LIMIT_DOWN")
		if sLn == 0 && dLn == 0 {
			sOut, _ := runSubtreeIptCmd(iptBin, "-t", "mangle", "-S", "POSTROUTING")
			sLn = findIptFirstChainRuleLine(lOut, sOut, "HNC_SAVE")
			dLn = findIptFirstChainRuleLine(lOut, sOut, "HNC_APP_LIMIT_DOWN")
		}
		return sLn, dLn
	}

	saveLn, downLn := locatePostLines()
	_, hasDownErr := runSubtreeIptCmd(iptBin, "-t", "mangle", "-C", "POSTROUTING", "-j", "HNC_APP_LIMIT_DOWN")
	if hasDownErr == nil && saveLn > 0 && downLn > saveLn {
		// 若已有 HNC_APP_LIMIT_DOWN 误排在 HNC_SAVE 之后, 先摘除再重插到 HNC_SAVE 之前
		_, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-D", "POSTROUTING", "-j", "HNC_APP_LIMIT_DOWN")
		saveLn, _ = locatePostLines()
		hasDownErr = errors.New("reinsert HNC_APP_LIMIT_DOWN before HNC_SAVE")
	}
	if hasDownErr != nil {
		ensureChainExists("mangle", "HNC_APP_LIMIT_DOWN")
		if saveLn > 0 {
			if _, iErr := runSubtreeIptCmd(iptBin, "-t", "mangle", "-I", "POSTROUTING", strconv.Itoa(saveLn), "-j", "HNC_APP_LIMIT_DOWN"); iErr != nil {
				_, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-A", "POSTROUTING", "-j", "HNC_APP_LIMIT_DOWN")
			}
		} else {
			if _, iErr := runSubtreeIptCmd(iptBin, "-t", "mangle", "-I", "POSTROUTING", "1", "-j", "HNC_APP_LIMIT_DOWN"); iErr != nil {
				_, _ = runSubtreeIptCmd(iptBin, "-t", "mangle", "-A", "POSTROUTING", "-j", "HNC_APP_LIMIT_DOWN")
			}
		}
	}
}

func (s *server) apiV6NativeSubtreesGet(w http.ResponseWriter, _ *http.Request) {
	ratios := s.CurrentDynamicQoSRatios()
	globalV6Subtrees.mu.RLock()
	lastRestore := globalV6Subtrees.lastRestore
	globalV6Subtrees.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"qos_ratios":   ratios,
		"last_restore": lastRestore,
		"counters": map[string]uint64{
			"app_limit_applies": globalV6Subtrees.appLimitApplies.Load(),
			"app_qos_applies":   globalV6Subtrees.appQoSApplies.Load(),
			"dynamic_tunes":     globalV6Subtrees.dynamicTunes.Load(),
			"full_restores":     globalV6Subtrees.fullRestores.Load(),
			"v6_neigh_syncs":    globalV6Subtrees.v6NeighSyncs.Load(),
		},
	})
}

func (s *server) apiV6NativeSubtreesPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action     string  `json:"action"`
		JitterMs   float64 `json:"jitter_ms"`
		DeltaRTTMs float64 `json:"delta_rtt_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	switch strings.TrimSpace(req.Action) {
	case "full_restore", "":
		s.actionMu.Lock()
		rep, err := s.NativeFullRestoreV6()
		s.actionMu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error(), "report": rep, "dynamic_qos": rep.QoSRatios})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "report": rep, "dynamic_qos": rep.QoSRatios})
	case "tune_qos":
		ratios, changed := globalV6Subtrees.SmoothStepDynamicQoS(req.JitterMs, req.DeltaRTTMs)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "qos_ratios": ratios})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unknown action"})
	}
}
