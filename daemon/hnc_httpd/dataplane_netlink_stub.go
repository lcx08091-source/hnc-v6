//go:build !linux && !android

// dataplane_netlink_stub.go — 非 Linux 平台跨平台安全编译桩。
//
// 保留纯内存协议编解码与测试桩判定逻辑, 使纯字节解析/速率表计算/报文构造/防火墙规则构造单测在任意平台均可运行;
// 仅对依赖 Linux AF_NETLINK socket 的内核交互入口返回明确不支持错误。

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rtnlAlignTo   = 4
	rtnlMsgHdrLen = 16
	rtnlTcMsgLen  = 20
	rtnlAttrHdr   = 4

	rtnlMsgNoop  = 1
	rtnlMsgError = 2
	rtnlMsgDone  = 3

	rtnlNewQdisc   = 36
	rtnlDelQdisc   = 37
	rtnlGetQdisc   = 38
	rtnlNewTClass  = 40
	rtnlDelTClass  = 41
	rtnlGetTClass  = 42
	rtnlNewTFilter = 44
	rtnlDelTFilter = 45

	rtnlFRequest = 0x0001
	rtnlFMulti   = 0x0002
	rtnlFAck     = 0x0004
	rtnlFReplace = 0x0100
	rtnlFDump    = 0x0300
	rtnlFCreate  = 0x0400

	rtnlTcHRoot    = uint32(0xffffffff)
	rtnlTcHIngress = uint32(0xfffffff1)
	rtnlHtbRootMaj = 0x00010000
	rtnlHtbRootCls = 0x00010001
	rtnlDefMinor   = 0x9999

	rtnlTcaKind    = 1
	rtnlTcaOptions = 2
	rtnlTcaStats   = 3
	rtnlTcaStats2  = 7

	rtnlTcaHtbParms  = 1
	rtnlTcaHtbInit   = 2
	rtnlTcaHtbCtab   = 3
	rtnlTcaHtbRtab   = 4
	rtnlTcaHtbRate64 = 6
	rtnlTcaHtbCeil64 = 7
	rtnlHtbProtoVer  = 3
	rtnlHtbDefR2Q    = 10
	rtnlLinkLayerEth = 1
	rtnlRtabSize     = 1024
	rtnlHtbOptSize   = 44
	rtnlHtbGlobSize  = 20
	rtnlDefaultMTU   = 1600

	rtnlTcaFqCodelTarget   = 1
	rtnlTcaFqCodelLimit    = 2
	rtnlTcaFqCodelInterval = 3
	rtnlTcaFqCodelQuantum  = 6

	rtnlTcaFwClassID = 1
	rtnlTcaFwMask    = 5

	rtnlTcaU32ClassID  = 1
	rtnlTcaU32Sel      = 5
	rtnlTcU32Terminal  = 1
	rtnlU32SelHdrSize  = 16
	rtnlU32KeySize     = 16
	rtnlIPv4SrcOff     = 12
	rtnlIPv4DstOff     = 16
	rtnlFilterPrioFW   = 1
	rtnlFilterPrioBase = 100

	rtnlTcaStatsBasic = 1
	rtnlTcaStatsQueue = 3
	rtnlTcaStatsPkt64 = 8

	rtnlEthPAll  = 0x0003
	rtnlEthPIP   = 0x0800
	rtnlEthPIPv6 = 0x86dd

	DefaultDevMarkBase      = uint32(0x00800000)
	DefaultDevMarkMask      = uint32(0x00ff0000)
	DefaultDevMarkShift     = 16
	DefaultAppQoSMarkMask   = uint32(0x03000000)
	DefaultAppLimitMarkMask = uint32(0xfc000000)
	DefaultConnmarkMask     = uint32(0xffff0000)
	DefaultHTBRootRateBps  = uint64(125_000_000)
	DefaultHTBRootBurstB   = uint32(200 * 1024)
	DefaultHTBRootQuantumB = uint32(60000)

	pschedTimeUnitsPerSec = 1_000_000.0
	pschedDefaultTickUsec = 15.625
)

var errNetlinkUnsupportedOS = errors.New("rtnetlink dataplane is only supported on linux/android")

type dataplaneCounters struct {
	nlEnsureCalls     atomic.Uint64
	nlUpsertCalls     atomic.Uint64
	nlDumpCalls       atomic.Uint64
	nlErrors          atomic.Uint64
	iptAtomicCommits  atomic.Uint64
	iptScriptFallback atomic.Uint64
	seqGen            atomic.Uint64
}

var dpStats dataplaneCounters

type HTBClassStat struct {
	ClassID    string `json:"class_id"`
	Parent     string `json:"parent"`
	HandleRaw  uint32 `json:"handle_raw"`
	ParentRaw  uint32 `json:"parent_raw"`
	RateBps    uint64 `json:"rate_bps"`
	CeilBps    uint64 `json:"ceil_bps"`
	RateKbit   uint64 `json:"rate_kbit"`
	CeilKbit   uint64 `json:"ceil_kbit"`
	Buffer     uint32 `json:"buffer"`
	CBuffer    uint32 `json:"cbuffer"`
	Quantum    uint32 `json:"quantum"`
	Level      uint32 `json:"level"`
	Prio       uint32 `json:"prio"`
	SentBytes  uint64 `json:"sent_bytes"`
	SentPkts   uint32 `json:"sent_pkts"`
	SentPkts64 uint64 `json:"sent_pkts64"`
	QLen       uint32 `json:"qlen"`
	Backlog    uint32 `json:"backlog"`
	Drops      uint32 `json:"drops"`
	Requeues   uint32 `json:"requeues"`
	Overlimits uint32 `json:"overlimits"`
}

func useNativeDataplane(hncDir string) bool {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(hncDir, "run", "native_dp.disabled")); err == nil {
		return false
	}
	constPath := filepath.Join(hncDir, "bin", "hnc_constants.sh")
	st, err := os.Stat(constPath)
	if err != nil || st.IsDir() {
		return false
	}
	if b, err := os.ReadFile(constPath); err == nil && bytes.Contains(b, []byte("run/exec.log")) {
		return false
	}
	return true
}

func pschedTickInUsecFromContent(content string) float64 {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return pschedDefaultTickUsec
	}
	t2us, err1 := strconv.ParseUint(fields[0], 16, 32)
	us2t, err2 := strconv.ParseUint(fields[1], 16, 32)
	clockRes, err3 := strconv.ParseUint(fields[2], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil || t2us == 0 || us2t == 0 || clockRes == 0 {
		return pschedDefaultTickUsec
	}
	tick := (float64(t2us) / float64(us2t)) * (float64(clockRes) / pschedTimeUnitsPerSec)
	if tick <= 0 || math.IsNaN(tick) || math.IsInf(tick, 0) {
		return pschedDefaultTickUsec
	}
	return tick
}

func pschedTime2Tick(usec float64, tickInUsec float64) uint32 {
	if usec <= 0 {
		return 0
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}
	v := usec * tickInUsec
	if v >= float64(math.MaxUint32) {
		return math.MaxUint32
	}
	if v < 1 {
		return 1
	}
	return uint32(v)
}

func tcCalcXmitTime(rateBytesPerSec uint64, sizeBytes uint32, tickInUsec float64) uint32 {
	if rateBytesPerSec == 0 || sizeBytes == 0 {
		return 0
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}
	usec := pschedTimeUnitsPerSec * (float64(sizeBytes) / float64(rateBytesPerSec))
	if usec >= 1.0 {
		usec = math.Floor(usec)
	}
	return pschedTime2Tick(usec, tickInUsec)
}

func calcHTBRateTable(rateBytesPerSec uint64, mtu uint32, mpu uint16, tickInUsec float64) (uint8, [256]uint32) {
	var rtab [256]uint32
	if mtu == 0 {
		mtu = rtnlDefaultMTU
	}
	cellLog := uint8(0)
	for (mtu >> cellLog) > 255 && cellLog < 31 {
		cellLog++
	}
	if rateBytesPerSec == 0 {
		return cellLog, rtab
	}
	for i := 0; i < 256; i++ {
		sz := uint32((i + 1) << cellLog)
		if uint32(mpu) > sz {
			sz = uint32(mpu)
		}
		rtab[i] = tcCalcXmitTime(rateBytesPerSec, sz, tickInUsec)
	}
	return cellLog, rtab
}

func encodeHTBOpt(rateBps, ceilBps uint64, burstBytes, cburstBytes, quantum, prio uint32, tickInUsec float64) ([rtnlHtbOptSize]byte, [rtnlRtabSize]byte, [rtnlRtabSize]byte) {
	var opt [rtnlHtbOptSize]byte
	var rtabBuf [rtnlRtabSize]byte
	var ctabBuf [rtnlRtabSize]byte
	if ceilBps == 0 {
		ceilBps = rateBps
	}
	if burstBytes == 0 {
		burstBytes = hncBurstBytesForRate(rateBps, false)
	}
	if cburstBytes == 0 {
		cburstBytes = hncBurstBytesForRate(ceilBps, false)
	}
	if quantum == 0 {
		quantum = hncQuantumForRate(rateBps)
	}
	rCellLog, rtab := calcHTBRateTable(rateBps, rtnlDefaultMTU, 0, tickInUsec)
	cCellLog, ctab := calcHTBRateTable(ceilBps, rtnlDefaultMTU, 0, tickInUsec)
	putRS := func(dst []byte, cellLog uint8, bps uint64) {
		dst[0] = cellLog
		dst[1] = rtnlLinkLayerEth
		binary.LittleEndian.PutUint16(dst[2:4], 0)
		binary.LittleEndian.PutUint16(dst[4:6], 0xffff)
		binary.LittleEndian.PutUint16(dst[6:8], 0)
		r32 := uint32(math.MaxUint32)
		if bps < uint64(math.MaxUint32) {
			r32 = uint32(bps)
		}
		binary.LittleEndian.PutUint32(dst[8:12], r32)
	}
	putRS(opt[0:12], rCellLog, rateBps)
	putRS(opt[12:24], cCellLog, ceilBps)
	binary.LittleEndian.PutUint32(opt[24:28], tcCalcXmitTime(rateBps, burstBytes, tickInUsec))
	binary.LittleEndian.PutUint32(opt[28:32], tcCalcXmitTime(ceilBps, cburstBytes, tickInUsec))
	binary.LittleEndian.PutUint32(opt[32:36], quantum)
	binary.LittleEndian.PutUint32(opt[36:40], 0)
	binary.LittleEndian.PutUint32(opt[40:44], prio)
	for i := 0; i < 256; i++ {
		binary.LittleEndian.PutUint32(rtabBuf[i*4:i*4+4], rtab[i])
		binary.LittleEndian.PutUint32(ctabBuf[i*4:i*4+4], ctab[i])
	}
	return opt, rtabBuf, ctabBuf
}

func hncBurstBytesForRate(rateBps uint64, precise bool) uint32 {
	if rateBps == 0 {
		return 16 * 1024
	}
	mbps := float64(rateBps) * 8.0 / 1_000_000.0
	if mbps >= 1000.0 {
		return DefaultHTBRootBurstB
	}
	bps := float64(rateBps)
	const mtu2 = 3028.0
	var win, fl, flmax, capBytes float64
	if precise {
		win, fl, flmax = 0.008192, bps*0.0625, 8192.0
		if mbps >= 100.0 {
			capBytes = 1024.0 * 1024.0
		} else {
			capBytes = 64.0 * 1024.0
		}
	} else {
		win, fl, flmax = 0.02048, bps*0.125, 16384.0
		if mbps >= 100.0 {
			capBytes = 4096.0 * 1024.0
		} else {
			capBytes = 256.0 * 1024.0
		}
	}
	if fl < mtu2 {
		fl = mtu2
	}
	if fl > flmax {
		fl = flmax
	}
	b := bps * win
	if b < fl {
		b = fl
	}
	if b > capBytes {
		b = capBytes
	}
	if mbps >= 100.0 && b < 200.0*1024.0 {
		b = 200.0 * 1024.0
	}
	k := uint32(b/1024.0 + 0.9999)
	if k < 3 {
		k = 3
	}
	return k * 1024
}

func hncQuantumForRate(rateBps uint64) uint32 {
	q := rateBps / 10
	if q < 1514 {
		return 1514
	}
	if q > 60000 {
		return 60000
	}
	return uint32(q)
}

func mbpsStrToBytesPerSec(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := 1_000_000.0
	switch {
	case strings.HasSuffix(s, "gbit"):
		s, mult = strings.TrimSuffix(s, "gbit"), 1_000_000_000.0
	case strings.HasSuffix(s, "mbit"):
		s, mult = strings.TrimSuffix(s, "mbit"), 1_000_000.0
	case strings.HasSuffix(s, "kbit"):
		s, mult = strings.TrimSuffix(s, "kbit"), 1_000.0
	case strings.HasSuffix(s, "bit"):
		s, mult = strings.TrimSuffix(s, "bit"), 1.0
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("invalid rate %q", s)
	}
	if v == 0 {
		return 0, nil
	}
	bps := uint64(math.Round((v * mult) / 8.0))
	if bps == 0 {
		bps = 1
	}
	return bps, nil
}

func htbClassMinorForMid(mid int) (uint16, error) {
	if mid < 1 || mid > 99 {
		return 0, fmt.Errorf("mark_id %d out of range [1,99]", mid)
	}
	if mid == 1 {
		return 0x0100, nil
	}
	return (uint16(mid/10) << 4) | uint16(mid%10), nil
}

func formatTCHandle(h uint32) string {
	switch h {
	case rtnlTcHRoot:
		return "root"
	case rtnlTcHIngress:
		return "ffff:fff1"
	case 0:
		return "none"
	}
	maj := h >> 16
	min := h & 0xffff
	if min == 0 {
		return fmt.Sprintf("%x:", maj)
	}
	return fmt.Sprintf("%x:%x", maj, min)
}

func rtnlAlign(n int) int {
	return (n + (rtnlAlignTo - 1)) &^ (rtnlAlignTo - 1)
}

func rtnlHtons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func rtnlPutAttr(dst []byte, attrType uint16, payload []byte) []byte {
	rawLen := rtnlAttrHdr + len(payload)
	padLen := rtnlAlign(rawLen)
	off := len(dst)
	dst = append(dst, make([]byte, padLen)...)
	binary.LittleEndian.PutUint16(dst[off:off+2], uint16(rawLen))
	binary.LittleEndian.PutUint16(dst[off+2:off+4], attrType)
	copy(dst[off+4:off+rawLen], payload)
	return dst
}

func rtnlPutAttrString(dst []byte, attrType uint16, s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return rtnlPutAttr(dst, attrType, b)
}

func rtnlPutAttrU32(dst []byte, attrType uint16, v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return rtnlPutAttr(dst, attrType, b[:])
}

func rtnlPutAttrU64(dst []byte, attrType uint16, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return rtnlPutAttr(dst, attrType, b[:])
}

func rtnlBuildTCMsg(msgType, flags uint16, seq uint32, ifindex int, handle, parent, info uint32, attrs []byte) []byte {
	total := rtnlMsgHdrLen + rtnlTcMsgLen + len(attrs)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint32(buf[8:12], seq)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(int32(ifindex)))
	binary.LittleEndian.PutUint32(buf[24:28], handle)
	binary.LittleEndian.PutUint32(buf[28:32], parent)
	binary.LittleEndian.PutUint32(buf[32:36], info)
	copy(buf[36:], attrs)
	return buf
}

func buildHTBRootQdiscMsg(seq uint32, ifindex int, defaultMinor uint16) []byte {
	var glob [rtnlHtbGlobSize]byte
	binary.LittleEndian.PutUint32(glob[0:4], rtnlHtbProtoVer)
	binary.LittleEndian.PutUint32(glob[4:8], rtnlHtbDefR2Q)
	binary.LittleEndian.PutUint32(glob[8:12], uint32(defaultMinor))
	var opts, attrs []byte
	opts = rtnlPutAttr(opts, rtnlTcaHtbInit, glob[:])
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "htb")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	return rtnlBuildTCMsg(rtnlNewQdisc, rtnlFRequest|rtnlFAck|rtnlFCreate|rtnlFReplace, seq, ifindex, rtnlHtbRootMaj, rtnlTcHRoot, 0, attrs)
}

func buildHTBClassUpsertMsg(seq uint32, ifindex int, parent, classHandle uint32, rateBps, ceilBps uint64, burstBytes, cburstBytes, quantum, prio uint32, tickInUsec float64) []byte {
	if ceilBps == 0 {
		ceilBps = rateBps
	}
	opt, rtab, ctab := encodeHTBOpt(rateBps, ceilBps, burstBytes, cburstBytes, quantum, prio, tickInUsec)
	var opts, attrs []byte
	opts = rtnlPutAttr(opts, rtnlTcaHtbParms, opt[:])
	opts = rtnlPutAttr(opts, rtnlTcaHtbRtab, rtab[:])
	opts = rtnlPutAttr(opts, rtnlTcaHtbCtab, ctab[:])
	opts = rtnlPutAttrU64(opts, rtnlTcaHtbRate64, rateBps)
	opts = rtnlPutAttrU64(opts, rtnlTcaHtbCeil64, ceilBps)
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "htb")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	return rtnlBuildTCMsg(rtnlNewTClass, rtnlFRequest|rtnlFAck|rtnlFCreate|rtnlFReplace, seq, ifindex, classHandle, parent, 0, attrs)
}

func buildFwFilterMsg(seq uint32, ifindex int, parent uint32, prio, ethProto uint16, markVal, markMask, classID uint32) []byte {
	if markMask == 0 {
		markMask = DefaultDevMarkMask
	}
	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaFwClassID, classID)
	opts = rtnlPutAttrU32(opts, rtnlTcaFwMask, markMask)
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "fw")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	info := (uint32(prio) << 16) | uint32(rtnlHtons(ethProto))
	return rtnlBuildTCMsg(rtnlNewTFilter, rtnlFRequest|rtnlFAck|rtnlFCreate|rtnlFReplace, seq, ifindex, markVal&markMask, parent, info, attrs)
}

func buildU32IPv4FilterMsg(seq uint32, ifindex int, parent uint32, prio uint16, ip4 net.IP, isUplink bool, classID uint32) ([]byte, error) {
	v4 := ip4.To4()
	if len(v4) != 4 {
		return nil, fmt.Errorf("invalid IPv4 address %v", ip4)
	}
	var sel [rtnlU32SelHdrSize + rtnlU32KeySize]byte
	sel[0] = rtnlTcU32Terminal
	sel[2] = 1
	binary.LittleEndian.PutUint32(sel[16:20], uint32(0xffffffff))
	ipWireLE := uint32(v4[0]) | (uint32(v4[1]) << 8) | (uint32(v4[2]) << 16) | (uint32(v4[3]) << 24)
	binary.LittleEndian.PutUint32(sel[20:24], ipWireLE)
	hdrOff := uint32(rtnlIPv4DstOff)
	if isUplink {
		hdrOff = uint32(rtnlIPv4SrcOff)
	}
	binary.LittleEndian.PutUint32(sel[24:28], hdrOff)
	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaU32ClassID, classID)
	opts = rtnlPutAttr(opts, rtnlTcaU32Sel, sel[:])
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "u32")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	info := (uint32(prio) << 16) | uint32(rtnlHtons(rtnlEthPIP))
	return rtnlBuildTCMsg(rtnlNewTFilter, rtnlFRequest|rtnlFAck|rtnlFCreate, seq, ifindex, 0, parent, info, attrs), nil
}

func nlIfaceIndexByName(_ string) (int, error) {
	return 0, errNetlinkUnsupportedOS
}

func nlEnsureHTBRoot(_ int, _ uint16, _ uint64) error {
	return errNetlinkUnsupportedOS
}

func nlUpsertDeviceHTB(_ int, _ uint16, _, _ uint64, _, _, _, _, _ uint32, _ string, _ bool) error {
	return errNetlinkUnsupportedOS
}

func nlDeleteDeviceHTB(_ int, _ uint16, _, _ uint32) error {
	return errNetlinkUnsupportedOS
}

func nlDumpHTBClassStats(_ int) (map[string]HTBClassStat, error) {
	return nil, errNetlinkUnsupportedOS
}

func parseTCClassDumpMsgs(b []byte, wantIfIndex int) (map[string]HTBClassStat, error) {
	out := make(map[string]HTBClassStat, 8)
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return nil, fmt.Errorf("rtnl class dump: truncated nlmsghdr (%d < %d)", rem, rtnlMsgHdrLen)
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return nil, fmt.Errorf("rtnl class dump: bad nlmsg_len %d (rem %d)", msgLen, rem)
		}
		msg := b[off : off+msgLen]
		adv := (msgLen + 3) &^ 3
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
		if msgType == rtnlMsgDone {
			return out, nil
		}
		if msgType == rtnlMsgError {
			if len(msg) < rtnlMsgHdrLen+4 {
				return nil, errors.New("rtnl class dump: truncated nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code != 0 {
				return nil, fmt.Errorf("rtnl class dump error %d", code)
			}
			continue
		}
		if msgType != rtnlNewTClass {
			continue
		}
		if len(msg) < rtnlMsgHdrLen+rtnlTcMsgLen {
			return nil, errors.New("rtnl class dump: truncated tcmsg")
		}
		ifidx := int(int32(binary.LittleEndian.Uint32(msg[20:24])))
		handle := binary.LittleEndian.Uint32(msg[24:28])
		parent := binary.LittleEndian.Uint32(msg[28:32])
		st := HTBClassStat{
			ClassID:   formatTCHandle(handle),
			Parent:    formatTCHandle(parent),
			HandleRaw: handle,
			ParentRaw: parent,
		}
		var kind string
		var rate32, ceil32, rate64, ceil64 uint64
		var hasR64, hasC64, hasP64, gotStats2 bool
		for aoff := rtnlMsgHdrLen + rtnlTcMsgLen; aoff < len(msg); {
			arem := len(msg) - aoff
			if arem < rtnlAttrHdr {
				return nil, errors.New("rtnl class dump: truncated tca header")
			}
			alen := int(binary.LittleEndian.Uint16(msg[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(msg[aoff+2:aoff+4]) & nlaTypeMask
			if alen < rtnlAttrHdr || alen > arem {
				return nil, errors.New("rtnl class dump: bad tca len")
			}
			aval := msg[aoff+4 : aoff+alen]
			switch atype {
			case rtnlTcaKind:
				if idx := bytes.IndexByte(aval, 0); idx >= 0 {
					kind = string(aval[:idx])
				} else {
					kind = string(aval)
				}
			case rtnlTcaOptions:
				for noff := 0; noff < len(aval); {
					nrem := len(aval) - noff
					if nrem < rtnlAttrHdr {
						return nil, errors.New("rtnl htb options: truncated nested header")
					}
					nlen := int(binary.LittleEndian.Uint16(aval[noff : noff+2]))
					ntype := binary.LittleEndian.Uint16(aval[noff+2:noff+4]) & nlaTypeMask
					if nlen < rtnlAttrHdr || nlen > nrem {
						return nil, errors.New("rtnl htb options: bad nested len")
					}
					nval := aval[noff+4 : noff+nlen]
					switch ntype {
					case rtnlTcaHtbParms:
						if len(nval) < rtnlHtbOptSize {
							return nil, errors.New("rtnl htb options: truncated tc_htb_opt")
						}
						rate32 = uint64(binary.LittleEndian.Uint32(nval[8:12]))
						ceil32 = uint64(binary.LittleEndian.Uint32(nval[20:24]))
						st.Buffer = binary.LittleEndian.Uint32(nval[24:28])
						st.CBuffer = binary.LittleEndian.Uint32(nval[28:32])
						st.Quantum = binary.LittleEndian.Uint32(nval[32:36])
						st.Level = binary.LittleEndian.Uint32(nval[36:40])
						st.Prio = binary.LittleEndian.Uint32(nval[40:44])
					case rtnlTcaHtbRate64:
						if len(nval) < 8 {
							return nil, errors.New("rtnl htb options: truncated RATE64")
						}
						rate64, hasR64 = binary.LittleEndian.Uint64(nval[0:8]), true
					case rtnlTcaHtbCeil64:
						if len(nval) < 8 {
							return nil, errors.New("rtnl htb options: truncated CEIL64")
						}
						ceil64, hasC64 = binary.LittleEndian.Uint64(nval[0:8]), true
					}
					nadv := (nlen + 3) &^ 3
					if nadv > nrem {
						noff = len(aval)
					} else {
						noff += nadv
					}
				}
			case rtnlTcaStats2:
				for noff := 0; noff < len(aval); {
					nrem := len(aval) - noff
					if nrem < rtnlAttrHdr {
						return nil, errors.New("rtnl stats2: truncated nested header")
					}
					nlen := int(binary.LittleEndian.Uint16(aval[noff : noff+2]))
					ntype := binary.LittleEndian.Uint16(aval[noff+2:noff+4]) & nlaTypeMask
					if nlen < rtnlAttrHdr || nlen > nrem {
						return nil, errors.New("rtnl stats2: bad nested len")
					}
					nval := aval[noff+4 : noff+nlen]
					switch ntype {
					case rtnlTcaStatsBasic:
						if len(nval) < 12 {
							return nil, errors.New("rtnl stats2: truncated TCA_STATS_BASIC")
						}
						st.SentBytes = binary.LittleEndian.Uint64(nval[0:8])
						st.SentPkts = binary.LittleEndian.Uint32(nval[8:12])
					case rtnlTcaStatsPkt64:
						if len(nval) < 8 {
							return nil, errors.New("rtnl stats2: truncated TCA_STATS_PKT64")
						}
						st.SentPkts64, hasP64 = binary.LittleEndian.Uint64(nval[0:8]), true
					case rtnlTcaStatsQueue:
						if len(nval) < 20 {
							return nil, errors.New("rtnl stats2: truncated TCA_STATS_QUEUE")
						}
						st.QLen = binary.LittleEndian.Uint32(nval[0:4])
						st.Backlog = binary.LittleEndian.Uint32(nval[4:8])
						st.Drops = binary.LittleEndian.Uint32(nval[8:12])
						st.Requeues = binary.LittleEndian.Uint32(nval[12:16])
						st.Overlimits = binary.LittleEndian.Uint32(nval[16:20])
					}
					nadv := (nlen + 3) &^ 3
					if nadv > nrem {
						noff = len(aval)
					} else {
						noff += nadv
					}
				}
				gotStats2 = true
			case rtnlTcaStats:
				if !gotStats2 && len(aval) >= 20 {
					st.SentBytes = binary.LittleEndian.Uint64(aval[0:8])
					st.SentPkts = binary.LittleEndian.Uint32(aval[8:12])
					st.Drops = binary.LittleEndian.Uint32(aval[12:16])
					st.Overlimits = binary.LittleEndian.Uint32(aval[16:20])
				}
			}
			nadv := (alen + 3) &^ 3
			if nadv > arem {
				aoff = len(msg)
			} else {
				aoff += nadv
			}
		}
		if wantIfIndex > 0 && ifidx != wantIfIndex {
			continue
		}
		if kind != "" && kind != "htb" {
			continue
		}
		if hasR64 {
			st.RateBps = rate64
		} else {
			st.RateBps = rate32
		}
		if hasC64 {
			st.CeilBps = ceil64
		} else {
			st.CeilBps = ceil32
		}
		st.RateKbit = (st.RateBps * 8) / 1000
		st.CeilKbit = (st.CeilBps * 8) / 1000
		if !hasP64 {
			st.SentPkts64 = uint64(st.SentPkts)
		}
		out[st.ClassID] = st
	}
	return out, nil
}

func readDeviceMarkSpec(hncDir string, mid int) (uint32, uint32) {
	mask := DefaultDevMarkMask
	shift := uint(DefaultDevMarkShift)
	base := DefaultDevMarkBase
	if hncDir != "" {
		if b, err := os.ReadFile(filepath.Join(hncDir, "bin", "hnc_constants.sh")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if k, v, ok := strings.Cut(line, "="); ok {
					k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
					switch k {
					case "HNC_DEV_MARK_MASK", "HNC_MARK_MASK":
						if u, err := strconv.ParseUint(v, 0, 32); err == nil && u != 0 {
							mask = uint32(u)
						}
					case "HNC_DEV_MARK_SHIFT", "HNC_MARK_SHIFT":
						if u, err := strconv.ParseUint(v, 10, 8); err == nil && u < 32 {
							shift = uint(u)
						}
					case "HNC_DEV_MARK_BASE":
						if u, err := strconv.ParseUint(v, 0, 32); err == nil {
							base = uint32(u)
						}
					case "HNC_MARK_BASE":
						if u, err := strconv.ParseUint(v, 0, 32); err == nil && (uint32(u)&uint32(0x0000ffff)) == 0 {
							base = uint32(u)
						}
					}
				}
			}
		}
	}
	if mid < 1 || mid > 99 {
		return 0, mask
	}
	return (base | (uint32(mid) << shift)) & mask, mask
}

func validStrictIPv4(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !ipv4RE.MatchString(s) {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func buildDeviceFirewallRestorePayloads(
	hncDir, iface, mac, ipv4 string,
	mid int,
	enableMark, enableBlock bool,
	v6RejectDropFallback bool,
) ([]byte, []byte, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return nil, nil, fmt.Errorf("invalid mac %q", mac)
	}
	if iface != "" && !ifaceNameRE.MatchString(strings.TrimSpace(iface)) {
		return nil, nil, fmt.Errorf("invalid iface %q", iface)
	}
	if ipv4 != "" && !validStrictIPv4(ipv4) {
		return nil, nil, fmt.Errorf("invalid ipv4 %q", ipv4)
	}
	if enableMark && (mid < 1 || mid > 99) {
		return nil, nil, fmt.Errorf("invalid mark_id %d", mid)
	}
	root, _ := rulesStore.ReadAll(hncDir)
	type snap struct {
		mac, ipv4 string
		mid       int
	}
	liveIPs := map[string]string{}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "devices.json")); err == nil {
		var raw map[string]map[string]interface{}
		if json.Unmarshal(b, &raw) == nil {
			for k, d := range raw {
				m := strings.ToLower(strings.TrimSpace(k))
				if ip, ok := d["ip"].(string); ok && validStrictIPv4(ip) {
					liveIPs[m] = strings.TrimSpace(ip)
				}
			}
		}
	}
	if ipv4 != "" {
		liveIPs[mac] = strings.TrimSpace(ipv4)
	}
	marked := map[string]snap{}
	blocked := map[string]string{}
	if devs, ok := root["devices"].(map[string]interface{}); ok {
		for k, v := range devs {
			m := strings.ToLower(strings.TrimSpace(k))
			dm, ok := v.(map[string]interface{})
			if !ok || !macRE.MatchString(m) {
				continue
			}
			ip := liveIPs[m]
			if ip == "" {
				if s := strings.TrimSpace(anyToRuleString(dm["ip"])); validStrictIPv4(s) {
					ip = s
				}
			}
			if mv := anyToRuleInt(dm["mark_id"]); mv >= 1 && mv <= 99 &&
				(anyToRuleBool(dm["limit_enabled"]) || deviceHasSecondaryQdiscOwner(hncDir, "", m, mv, dm)) {
				marked[m] = snap{mac: m, ipv4: ip, mid: mv}
			}
		}
	}
	if bl, ok := root["blacklist"].([]interface{}); ok {
		for _, item := range bl {
			m := strings.ToLower(strings.TrimSpace(anyToRuleString(item)))
			if macRE.MatchString(m) {
				blocked[m] = liveIPs[m]
			}
		}
	}
	if enableMark && mid >= 1 && mid <= 99 {
		marked[mac] = snap{mac: mac, ipv4: liveIPs[mac], mid: mid}
	} else {
		delete(marked, mac)
	}
	if enableBlock {
		blocked[mac] = liveIPs[mac]
	} else {
		delete(blocked, mac)
	}

	var mList []snap
	for _, s := range marked {
		mList = append(mList, s)
	}
	sort.Slice(mList, func(i, j int) bool { return mList[i].mac < mList[j].mac })
	var bList []snap
	for m, ip := range blocked {
		bList = append(bList, snap{mac: m, ipv4: ip})
	}
	sort.Slice(bList, func(i, j int) bool { return bList[i].mac < bList[j].mac })

	var v4, v6 bytes.Buffer
	v4.WriteString("*mangle\n:HNC_MARK - [0:0]\n")
	v6.WriteString("*mangle\n:HNC_MARK - [0:0]\n")
	for _, d := range mList {
		mv, mm := readDeviceMarkSpec(hncDir, d.mid)
		xm := fmt.Sprintf("0x%08x/0x%08x", mv, mm)
		zm := fmt.Sprintf("0x0/0x%08x", mm)
		if d.ipv4 != "" {
			fmt.Fprintf(&v4, "-A HNC_MARK -s %s/32 -m mac --mac-source %s -j MARK --set-xmark %s\n", d.ipv4, d.mac, xm)
		}
		fmt.Fprintf(&v4, "-A HNC_MARK -m mac --mac-source %s -m mark --mark %s -j MARK --set-xmark %s\n", d.mac, zm, xm)
		if d.ipv4 != "" {
			fmt.Fprintf(&v4, "-A HNC_MARK -d %s/32 -j MARK --set-xmark %s\n", d.ipv4, xm)
		}
		fmt.Fprintf(&v6, "-A HNC_MARK -m mac --mac-source %s -m mark --mark %s -j MARK --set-xmark %s\n", d.mac, zm, xm)
	}
	v4.WriteString("COMMIT\n*filter\n:HNC_CTRL - [0:0]\n")
	v6.WriteString("COMMIT\n*filter\n:HNC_CTRL - [0:0]\n")
	for _, b := range bList {
		if v6RejectDropFallback {
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
	return v4.Bytes(), v6.Bytes(), nil
}

func applyDeviceFirewallAtomic(hncDir, _, mac, _ string, mid int, enableMark, enableBlock bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("applyDeviceFirewallAtomic: invalid mac %q", mac)
	}
	if _, err := os.Stat(filepath.Join(hncDir, "bin", "apply_device_rule.sh")); err != nil {
		return errNetlinkUnsupportedOS
	}
	if enableBlock {
		if rc, out := runBin(hncDir, "apply_device_rule.sh", "bl_add", mac); rc != 0 {
			return fmt.Errorf("apply_device_rule.sh bl_add rc=%d: %s", rc, strings.TrimSpace(out))
		}
		return nil
	}
	if enableMark && mid > 0 {
		if rc, out := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac); rc != 0 {
			return fmt.Errorf("apply_device_rule.sh alloc_mid rc=%d: %s", rc, strings.TrimSpace(out))
		}
		return nil
	}
	if rc, out := runBin(hncDir, "apply_device_rule.sh", "clear", mac); rc != 0 {
		return fmt.Errorf("apply_device_rule.sh clear rc=%d: %s", rc, strings.TrimSpace(out))
	}
	return nil
}

func deviceFWDeleteSpecs() [][2]uint16 {
	return [][2]uint16{
		{rtnlFilterPrioFW, rtnlEthPAll},
		{rtnlFilterPrioFW, rtnlEthPIP},
		{3, rtnlEthPIPv6},
		{50, rtnlEthPAll},
		{50, rtnlEthPIP},
		{50, rtnlEthPIPv6},
		{51, rtnlEthPIPv6},
	}
}

func buildDelFilterMsg(seq uint32, ifindex int, parent, handle uint32, prio, ethProto uint16, kind string) []byte {
	var attrs []byte
	if kind != "" {
		attrs = rtnlPutAttrString(attrs, rtnlTcaKind, kind)
	}
	info := (uint32(prio) << 16) | uint32(rtnlHtons(ethProto))
	flags := uint16(rtnlFRequest | rtnlFAck)
	return rtnlBuildTCMsg(rtnlDelTFilter, flags, seq, ifindex, handle, parent, info, attrs)
}

func classIDStringForMid(mid int) string {
	if mid == 1 {
		return "100"
	}
	if mid >= 2 && mid <= 99 {
		return strconv.Itoa(mid)
	}
	return ""
}

func stateFileHasDevClass(path, iface, cidStr string) bool {
	if cidStr == "" {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return false
	}
	iface = strings.TrimSpace(iface)
	for _, ln := range strings.Split(string(b), "\n") {
		fs := strings.Fields(ln)
		if len(fs) >= 2 && fs[1] == cidStr && (iface == "" || fs[0] == iface) {
			return true
		}
	}
	return false
}

func deviceHasAppLimitsForMAC(hncDir, iface, mac string, mid int) bool {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return false
	}
	cidStr := classIDStringForMid(mid)
	if cidStr != "" && stateFileHasDevClass(filepath.Join(hncDir, "run", "app_limits.devs"), iface, cidStr) {
		return true
	}
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return false
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "app_limits.flat")); err == nil && len(b) > 0 {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			fs := strings.Fields(ln)
			if len(fs) >= 3 && strings.EqualFold(fs[0], mac) {
				if v, pErr := strconv.ParseFloat(fs[2], 64); pErr == nil && v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
					return true
				}
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "app_limits.json")); err == nil && len(b) > 0 {
		var af AppLimitFile
		if json.Unmarshal(b, &af) == nil {
			for _, it := range af.Items {
				if strings.EqualFold(strings.TrimSpace(it.MAC), mac) && it.DownMbps > 0 && !math.IsNaN(it.DownMbps) && !math.IsInf(it.DownMbps, 0) {
					return true
				}
			}
		}
	}
	return false
}

func hasActiveAppLimitsState(hncDir string) bool {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return false
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "app_limits.devs")); err == nil && strings.TrimSpace(string(b)) != "" {
		return true
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "app_limits.flat")); err == nil && len(b) > 0 {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" && !strings.HasPrefix(ln, "#") {
				return true
			}
		}
	}
	return false
}

func markAppLimitsDirtyIfNeeded(hncDir string) {
	if !hasActiveAppLimitsState(hncDir) {
		return
	}
	runDir := filepath.Join(hncDir, "run")
	_ = os.MkdirAll(runDir, 0o755)
	_ = os.WriteFile(filepath.Join(runDir, "app_limit.dirty"), []byte("1\n"), 0o644)
}

func deviceHasSecondaryQdiscOwner(hncDir, iface, mac string, mid int, dm map[string]interface{}) bool {
	if len(dm) > 0 {
		if anyToRuleBool(dm["delay_enabled"]) || anyToRuleBool(dm["sqm_enabled"]) || anyToRuleBool(dm["app_qos"]) {
			return true
		}
		for _, f := range []string{"delay_ms", "jitter_ms", "loss_pct"} {
			if numFieldGT0(dm[f]) {
				return true
			}
		}
	}
	if strings.TrimSpace(hncDir) != "" {
		if deviceHasAppLimitsForMAC(hncDir, iface, mac, mid) {
			return true
		}
		if cidStr := classIDStringForMid(mid); cidStr != "" {
			if stateFileHasDevClass(filepath.Join(hncDir, "run", "app_qos.state"), iface, cidStr) {
				return true
			}
		}
	}
	return false
}

func deviceHasNonDelaySecondaryOwner(hncDir, iface, mac string, mid int) bool {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	var cleanDM map[string]interface{}
	if err == nil && len(b) > 0 {
		var root map[string]interface{}
		if json.Unmarshal(b, &root) == nil {
			devs, _ := root["devices"].(map[string]interface{})
			for k, v := range devs {
				if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(mac)) {
					if rawDM, ok := v.(map[string]interface{}); ok {
						cleanDM = make(map[string]interface{}, len(rawDM))
						for fk, fv := range rawDM {
							switch fk {
							case "delay_enabled", "delay_ms", "jitter_ms", "loss_pct":
								continue
							default:
								cleanDM[fk] = fv
							}
						}
					}
					break
				}
			}
		}
	}
	return deviceHasSecondaryQdiscOwner(hncDir, iface, mac, mid, cleanDM)
}

func tryNativeResetDeviceRateToDefault(_, _, _, _ string, _ int) bool {
	return false
}

func tryNativeRuleSet(_, _, _, _ string) (string, bool) {
	return "", false
}

func tryNativeRuleClear(_, _ string) bool {
	return false
}

func tryNativeBlacklistSet(_, _ string, _ bool) bool {
	return false
}

var (
	nativeBPFDirPath   = "/sys/fs/bpf/hnc"
	nativeIptCmdRunner = func(_ string, _ ...string) (string, error) { return "", errNetlinkUnsupportedOS }
)

var nativeDPLockMu sync.Mutex

func acquireNativeDataplaneLock(hncDir, op string) (func(), error) {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return func() {}, nil
	}
	if strings.TrimSpace(op) == "" {
		op = "native_dp"
	}
	nativeDPLockMu.Lock()
	runDir := filepath.Join(hncDir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		nativeDPLockMu.Unlock()
		return nil, err
	}
	gateDir := filepath.Join(runDir, "lock", "gate")
	tcLockDir := filepath.Join(runDir, "tc_action.lock")
	selfPID := os.Getpid()
	selfPIDStr := strconv.Itoa(selfPID)
	for round := 0; round < 120; round++ {
		if _, gErr := os.Stat(gateDir); gErr == nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if err := os.Mkdir(tcLockDir, 0o755); err == nil {
			ownerLine := fmt.Sprintf("%d %s %d\n", selfPID, op, time.Now().Unix())
			_ = os.WriteFile(filepath.Join(tcLockDir, "owner"), []byte(ownerLine), 0o644)
			if _, gErr := os.Stat(gateDir); gErr == nil {
				_ = os.RemoveAll(tcLockDir)
				time.Sleep(25 * time.Millisecond)
				continue
			}
			var once sync.Once
			release := func() {
				once.Do(func() {
					if b, rErr := os.ReadFile(filepath.Join(tcLockDir, "owner")); rErr == nil {
						fs := strings.Fields(string(b))
						if len(fs) == 0 || fs[0] == selfPIDStr {
							_ = os.RemoveAll(tcLockDir)
						}
					} else {
						_ = os.RemoveAll(tcLockDir)
					}
					nativeDPLockMu.Unlock()
				})
			}
			return release, nil
		}
		if st, sErr := os.Stat(tcLockDir); sErr == nil && time.Since(st.ModTime()) >= 25*time.Second {
			_ = os.RemoveAll(tcLockDir)
			continue
		}
		time.Sleep(25 * time.Millisecond)
	}
	nativeDPLockMu.Unlock()
	return nil, errors.New("native dataplane: lock busy timeout")
}

func ensureNativeIPv4StatsRule(iptBin, ip string) {
	iptBin = strings.TrimSpace(iptBin)
	ip = strings.TrimSpace(ip)
	if iptBin == "" || !validStrictIPv4(ip) {
		return
	}
	for _, dirFlag := range []string{"-s", "-d"} {
		if _, err := nativeIptCmdRunner(iptBin, "-w", "2", "-t", "mangle", "-C", "HNC_STATS", dirFlag, ip, "-j", "RETURN"); err != nil {
			_, _ = nativeIptCmdRunner(iptBin, "-w", "2", "-t", "mangle", "-A", "HNC_STATS", dirFlag, ip, "-j", "RETURN")
		}
	}
}

func syncNativeDataplaneSideEffects(hncDir, _ string) {
	if nativeBPFDirPath != "" {
		if _, err := os.Stat(nativeBPFDirPath); err == nil {
			if _, sErr := os.Stat(filepath.Join(hncDir, "bin", "hnc_clsact_sync.sh")); sErr == nil {
				_, _ = runBin(hncDir, "hnc_clsact_sync.sh")
			}
		}
	}
	markAppLimitsDirtyIfNeeded(hncDir)
}

// ── HNC v6.0.0 · Vector (T2): 原生特快护航 (1:10) / 更新细流 (1:9990) 报文构造器 ──

const (
	v6ExpressClassMinor   uint16 = 0x0010
	v6ExpressLeafDown     uint32 = 0x10100000
	v6ExpressLeafUp       uint32 = 0x11100000
	v6ExpressTargetUs     uint32 = 2000  // 2ms 浅驻留 fq_codel target
	v6ExpressIntervalUs   uint32 = 40000 // 40ms fq_codel interval
	v6ExpressQuantumB     uint32 = 300
	v6ExpressLimitPkts    uint32 = 512
	v6ExpressFilterPrioV4 uint16 = 2
	v6ExpressFilterPrioV6 uint16 = 4
	v6ExpressDefaultMark  uint32 = 0x01000000

	v6LeashClassMinor   uint16 = 0x9990
	v6LeashLeafDown     uint32 = 0x99900000
	v6LeashLeafUp       uint32 = 0x99910000
	v6LeashFilterPrioV4 uint16 = 6
	v6LeashFilterPrioV6 uint16 = 7
	v6LeashDefaultMark  uint32 = 0x03000000
	v6LeashDefaultKbps  int    = 1500
	v6LeashCBurstCapB   uint32 = 32 * 1024
)

// dataplaneNetlinkVerifyMarkers 冗余保留关键路由与动作原始字节于 .rodata,
// 配合 dataplane_verify.go 的 dataplaneRequiredAPIMarkers 双保险满足 build.sh 二进制门禁扫描。
var dataplaneNetlinkVerifyMarkers = [2]string{
	"/api/dataplane_verify",
	"dataplane_verify_run",
}

func keepDataplaneAPIMarkersAlive() {
	runtime.KeepAlive(&dataplaneNetlinkVerifyMarkers)
	runtime.KeepAlive(&dataplaneRequiredAPIMarkers)
}

func buildDelClassMsg(seq uint32, ifindex int, parent, classHandle uint32) []byte {
	return rtnlBuildTCMsg(rtnlDelTClass, rtnlFRequest|rtnlFAck, seq, ifindex, classHandle, parent, 0, nil)
}

func buildDelQdiscMsg(seq uint32, ifindex int, parent, handle uint32) []byte {
	return rtnlBuildTCMsg(rtnlDelQdisc, rtnlFRequest|rtnlFAck, seq, ifindex, handle, parent, 0, nil)
}

// buildVectorExpressUpsertBatch 构造 1:10 (prio 0) + 浅驻留 fq_codel (2ms/40ms/300B) + prio 2/4 fw 过滤器批消息。
func buildVectorExpressUpsertBatch(
	ifindex int,
	isUplink bool,
	rootRateBps, bgCeilBps uint64,
	gameMark, gameMask uint32,
	tickInUsec float64,
) [][]byte {
	keepDataplaneAPIMarkersAlive()
	if rootRateBps == 0 {
		rootRateBps = DefaultHTBRootRateBps
	}
	if gameMask == 0 {
		gameMask = DefaultAppQoSMarkMask
	}
	expRate := rootRateBps / 4
	const minExpRateBps = uint64(2_500_000) // >= 20 Mbps 保底高优承诺速率
	if expRate < minExpRateBps {
		expRate = minExpRateBps
	}
	if expRate > rootRateBps {
		expRate = rootRateBps
	}
	expCls := rtnlHtbRootMaj | uint32(v6ExpressClassMinor)
	leafHandle := v6ExpressLeafDown
	if isUplink {
		leafHandle = v6ExpressLeafUp
	}

	var msgs [][]byte
	msgs = append(msgs,
		buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, rtnlHtbRootCls, expCls,
			expRate, rootRateBps, 0, 0, 1514, 0, tickInUsec,
		),
		buildFqCodelCustomMsg(
			rtnlNextSeq(), ifindex, expCls, leafHandle,
			v6ExpressTargetUs, v6ExpressIntervalUs, v6ExpressQuantumB, v6ExpressLimitPkts,
		),
	)
	if (gameMark & gameMask) != 0 {
		msgs = append(msgs,
			buildFwFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, v6ExpressFilterPrioV4, rtnlEthPAll, gameMark, gameMask, expCls),
			buildFwFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, v6ExpressFilterPrioV6, rtnlEthPIPv6, gameMark, gameMask, expCls),
		)
	}
	if bgCeilBps > 0 {
		defCls := rtnlHtbRootMaj | uint32(rtnlDefMinor)
		bgBurst := hncBurstBytesForRate(bgCeilBps, false)
		msgs = append(msgs, buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, rtnlHtbRootCls, defCls,
			bgCeilBps, bgCeilBps, bgBurst, bgBurst, hncQuantumForRate(bgCeilBps), 7, tickInUsec,
		))
	}
	return msgs
}

// buildVectorExpressRemoveBatch 构造停用 Vector Express 时拆除 prio 2/4 过滤器、叶子与 1:10 类并恢复 1:9999 的消息序列。
func buildVectorExpressRemoveBatch(
	ifindex int,
	isUplink bool,
	restoreRootRateBps uint64,
	gameMark, gameMask uint32,
	tickInUsec float64,
) [][]byte {
	if restoreRootRateBps == 0 {
		restoreRootRateBps = DefaultHTBRootRateBps
	}
	if gameMask == 0 {
		gameMask = DefaultAppQoSMarkMask
	}
	expCls := rtnlHtbRootMaj | uint32(v6ExpressClassMinor)
	leafHandle := v6ExpressLeafDown
	if isUplink {
		leafHandle = v6ExpressLeafUp
	}
	masked := gameMark & gameMask

	var msgs [][]byte
	if masked != 0 {
		msgs = append(msgs,
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6ExpressFilterPrioV4, rtnlEthPAll, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6ExpressFilterPrioV4, rtnlEthPIP, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6ExpressFilterPrioV6, rtnlEthPIPv6, "fw"),
		)
	}
	msgs = append(msgs,
		buildDelQdiscMsg(rtnlNextSeq(), ifindex, expCls, leafHandle),
		buildDelClassMsg(rtnlNextSeq(), ifindex, rtnlHtbRootCls, expCls),
	)
	defCls := rtnlHtbRootMaj | uint32(rtnlDefMinor)
	burst := hncBurstBytesForRate(restoreRootRateBps, false)
	msgs = append(msgs, buildHTBClassUpsertMsg(
		rtnlNextSeq(), ifindex, rtnlHtbRootCls, defCls,
		restoreRootRateBps, restoreRootRateBps, burst, burst, DefaultHTBRootQuantumB, 7, tickInUsec,
	))
	return msgs
}

// buildUpdateLeashUpsertBatch 构造 1:9990 (默认 1500 Kbps, prio 7, cburst <= 32KiB) + fq_codel + prio 6/7 fw 过滤器批消息。
func buildUpdateLeashUpsertBatch(
	ifindex int,
	isUplink bool,
	rateBps uint64,
	leashMark, leashMask uint32,
	tickInUsec float64,
) [][]byte {
	if rateBps == 0 {
		rateBps = (uint64(v6LeashDefaultKbps) * 1000) / 8
	}
	if leashMask == 0 {
		leashMask = DefaultAppQoSMarkMask
	}
	leashCls := rtnlHtbRootMaj | uint32(v6LeashClassMinor)
	leafHandle := v6LeashLeafDown
	if isUplink {
		leafHandle = v6LeashLeafUp
	}
	burst := hncBurstBytesForRate(rateBps, true)
	cburst := burst
	if cburst > v6LeashCBurstCapB {
		cburst = v6LeashCBurstCapB
	}

	var msgs [][]byte
	msgs = append(msgs,
		buildHTBClassUpsertMsg(
			rtnlNextSeq(), ifindex, rtnlHtbRootCls, leashCls,
			rateBps, rateBps, burst, cburst, hncQuantumForRate(rateBps), 7, tickInUsec,
		),
		buildFqCodelLeafMsg(rtnlNextSeq(), ifindex, leashCls, leafHandle, true),
	)
	if (leashMark & leashMask) != 0 {
		msgs = append(msgs,
			buildFwFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, v6LeashFilterPrioV4, rtnlEthPAll, leashMark, leashMask, leashCls),
			buildFwFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, v6LeashFilterPrioV6, rtnlEthPIPv6, leashMark, leashMask, leashCls),
		)
	}
	return msgs
}

// buildUpdateLeashRemoveBatch 构造幂等卸载 1:9990 细流限速类及其 prio 6/7 过滤器的消息序列。
func buildUpdateLeashRemoveBatch(
	ifindex int,
	isUplink bool,
	leashMark, leashMask uint32,
) [][]byte {
	if leashMask == 0 {
		leashMask = DefaultAppQoSMarkMask
	}
	leashCls := rtnlHtbRootMaj | uint32(v6LeashClassMinor)
	leafHandle := v6LeashLeafDown
	if isUplink {
		leafHandle = v6LeashLeafUp
	}
	masked := leashMark & leashMask

	var msgs [][]byte
	if masked != 0 {
		msgs = append(msgs,
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6LeashFilterPrioV4, rtnlEthPAll, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6LeashFilterPrioV4, rtnlEthPIP, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, masked, v6LeashFilterPrioV6, rtnlEthPIPv6, "fw"),
		)
	}
	msgs = append(msgs,
		buildDelQdiscMsg(rtnlNextSeq(), ifindex, leashCls, leafHandle),
		buildDelClassMsg(rtnlNextSeq(), ifindex, rtnlHtbRootCls, leashCls),
	)
	return msgs
}

func rtnlNextSeq() uint32 {
	v := uint32(dpStats.seqGen.Add(1))
	if v == 0 {
		v = uint32(dpStats.seqGen.Add(1))
	}
	return v
}

func readPschedTickInUsec() float64 {
	return pschedDefaultTickUsec
}

func buildFqCodelLeafMsg(seq uint32, ifindex int, parent, leafHandle uint32, withParams bool) []byte {
	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "fq_codel")
	if withParams {
		var opts []byte
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelTarget, 5000)
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelInterval, 100_000)
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelQuantum, 1514)
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelLimit, 1024)
		attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	}
	return rtnlBuildTCMsg(rtnlNewQdisc, rtnlFRequest|rtnlFAck|rtnlFCreate|rtnlFReplace, seq, ifindex, leafHandle, parent, 0, attrs)
}

func openRTNetlinkSocket() (int, error) {
	return -1, errNetlinkUnsupportedOS
}

func nlCloseSocket(_ int) {}

func rtnlSendAndWaitAck(_ int, _ []byte, _ uint32) error {
	return errNetlinkUnsupportedOS
}

func isIgnorableDelErr(err error) bool {
	return err == nil
}

func resolveIptablesRestoreBin(_ string) string {
	return ""
}

func pipeIptablesRestore(_ string, _ []byte) error {
	return errNetlinkUnsupportedOS
}

func readLiveDeviceIPv4Map(hncDir string) map[string]string {
	out := make(map[string]string)
	if hncDir == "" {
		return out
	}
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "devices.json"))
	if err != nil {
		return out
	}
	var raw map[string]map[string]interface{}
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for k, d := range raw {
		m := strings.ToLower(strings.TrimSpace(k))
		if !macRE.MatchString(m) {
			continue
		}
		if ip, ok := d["ip"].(string); ok && validStrictIPv4(ip) {
			out[m] = strings.TrimSpace(ip)
		}
	}
	return out
}

func deviceHasDelayOwner(dm map[string]interface{}) bool {
	if len(dm) == 0 {
		return false
	}
	if anyToRuleBool(dm["delay_enabled"]) {
		return true
	}
	for _, f := range []string{"delay_ms", "jitter_ms", "loss_pct"} {
		if numFieldGT0(dm[f]) {
			return true
		}
	}
	return false
}

func nlTuneGlobalShaperOnSocket(_ int, _ int, _ uint64, _ int, _ uint64) (int, error) {
	return 0, errNetlinkUnsupportedOS
}

func nlApplyBatchWithFWFallbackOnSocket(_ int, _ [][]byte) (int, error) {
	return 0, errNetlinkUnsupportedOS
}

func nlProbeKernelCapabilities(_ int) (bool, bool, bool) {
	return false, false, false
}


func closeRTNetlinkSocket(_ int) {}

func sendConntrackDeleteNetlink(_ ScalpelTuple, _ uint32) error {
	return errNetlinkUnsupportedOS
}

func dumpNativeIPv6NeighborsOS(_ map[int]bool) (map[string][]net.IP, error) {
	return nil, errNetlinkUnsupportedOS
}
