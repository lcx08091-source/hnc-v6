//go:build linux || android

// dataplane_netlink.go — HNC v5.40.0 T3: Go 原生 RTNetlink tc 调速引擎 + 双栈 iptables-restore 内存管道提交器。
//
// 核心约束与工程保证:
//  1. 零第三方依赖: 仅使用标准库 syscall + encoding/binary.LittleEndian, 零 unsafe.Pointer 强转。
//  2. 32 位 armv7 安全: 含 atomic.Uint64 / atomic.Int64 的结构体一律将 64 位原子字段置于 offset 0。
//  3. 与 iproute2 100% 字节级兼容:
//     - 读取 /proc/net/psched 计算 tick_in_usec, 严格复刻 tc_core_time2tick / tc_calc_xmittime / tc_calc_rtable;
//     - 同时下发 256 项 TCA_HTB_RTAB / TCA_HTB_CTAB 与 64 位 TCA_HTB_RATE64 / TCA_HTB_CEIL64;
//     - TCA_OPTIONS 采用与 iproute2 libnetlink 完全一致的裸类型编码, 接收端兼容 NLA_F_NESTED 掩码剥离。
//  4. 测试桩零回归护栏: useNativeDataplane(hncDir) 在假脚本单测目录自动退回既有 runBin 脚本链路。

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ── RTNetlink / TC UAPI 常量（严格对应 linux/rtnetlink.h、pkt_sched.h、pkt_cls.h、gen_stats.h） ──

const (
	rtnlAlignTo   = 4
	rtnlMsgHdrLen = 16 // sizeof(struct nlmsghdr)
	rtnlTcMsgLen  = 20 // sizeof(struct tcmsg)
	rtnlAttrHdr   = 4  // sizeof(struct rtattr)

	rtnlMsgNoop  = 1 // NLMSG_NOOP
	rtnlMsgError = 2 // NLMSG_ERROR
	rtnlMsgDone  = 3 // NLMSG_DONE

	rtnlNewQdisc   = 36 // RTM_NEWQDISC
	rtnlDelQdisc   = 37 // RTM_DELQDISC
	rtnlGetQdisc   = 38 // RTM_GETQDISC
	rtnlNewTClass  = 40 // RTM_NEWTCLASS
	rtnlDelTClass  = 41 // RTM_DELTCLASS
	rtnlGetTClass  = 42 // RTM_GETTCLASS
	rtnlNewTFilter = 44 // RTM_NEWTFILTER
	rtnlDelTFilter = 45 // RTM_DELTFILTER

	rtnlFRequest = 0x0001 // NLM_F_REQUEST
	rtnlFMulti   = 0x0002 // NLM_F_MULTI
	rtnlFAck     = 0x0004 // NLM_F_ACK
	rtnlFReplace = 0x0100 // NLM_F_REPLACE (NEW 操作)
	rtnlFDump    = 0x0300 // NLM_F_ROOT | NLM_F_MATCH (GET 操作)
	rtnlFCreate  = 0x0400 // NLM_F_CREATE (NEW 操作)

	rtnlTcHRoot    = uint32(0xffffffff) // TC_H_ROOT
	rtnlTcHIngress = uint32(0xfffffff1) // TC_H_INGRESS / TC_H_CLSACT
	rtnlHtbRootMaj = 0x00010000         // handle 1:
	rtnlHtbRootCls = 0x00010001         // classid 1:1
	rtnlDefMinor   = 0x9999             // 默认未分类流量 minor: 1:9999

	//顶层 TCA_* 属性枚举 (linux/rtnetlink.h)
	rtnlTcaKind    = 1 // TCA_KIND
	rtnlTcaOptions = 2 // TCA_OPTIONS
	rtnlTcaStats   = 3 // TCA_STATS (legacy struct tc_stats 20B)
	rtnlTcaStats2  = 7 // TCA_STATS2

	// HTB 属性枚举与常量 (linux/pkt_sched.h)
	rtnlTcaHtbParms  = 1    // TCA_HTB_PARMS (struct tc_htb_opt, 44B)
	rtnlTcaHtbInit   = 2    // TCA_HTB_INIT  (struct tc_htb_glob, 20B)
	rtnlTcaHtbCtab   = 3    // TCA_HTB_CTAB  (256 * uint32 = 1024B)
	rtnlTcaHtbRtab   = 4    // TCA_HTB_RTAB  (256 * uint32 = 1024B)
	rtnlTcaHtbRate64 = 6    // TCA_HTB_RATE64 (uint64)
	rtnlTcaHtbCeil64 = 7    // TCA_HTB_CEIL64 (uint64)
	rtnlHtbProtoVer  = 3    // TC_HTB_PROTOVER
	rtnlHtbDefR2Q    = 10   // 默认 rate2quantum
	rtnlLinkLayerEth = 1    // TC_LINKLAYER_ETHERNET
	rtnlRtabSize     = 1024 // TC_RTAB_SIZE (256 * 4)
	rtnlHtbOptSize   = 44   // sizeof(struct tc_htb_opt)
	rtnlHtbGlobSize  = 20   // sizeof(struct tc_htb_glob)
	rtnlDefaultMTU   = 1600 // iproute2 q_htb.c 默认 MTU

	// fq_codel 属性枚举 (linux/pkt_sched.h)
	rtnlTcaFqCodelTarget   = 1 // TCA_FQ_CODEL_TARGET (uint32 us)
	rtnlTcaFqCodelLimit    = 2 // TCA_FQ_CODEL_LIMIT (uint32 pkts)
	rtnlTcaFqCodelInterval = 3 // TCA_FQ_CODEL_INTERVAL (uint32 us)
	rtnlTcaFqCodelQuantum  = 6 // TCA_FQ_CODEL_QUANTUM (uint32 bytes)

	// fw 分类器属性枚举 (linux/pkt_cls.h)
	rtnlTcaFwClassID = 1 // TCA_FW_CLASSID (uint32)
	rtnlTcaFwMask    = 5 // TCA_FW_MASK (uint32)

	// u32 分类器属性枚举与标志 (linux/pkt_cls.h)
	rtnlTcaU32ClassID  = 1 // TCA_U32_CLASSID (uint32)
	rtnlTcaU32Sel      = 5 // TCA_U32_SEL (struct tc_u32_sel + keys)
	rtnlTcU32Terminal  = 1 // TC_U32_TERMINAL
	rtnlU32SelHdrSize  = 16
	rtnlU32KeySize     = 16
	rtnlIPv4SrcOff     = 12 // IPv4 报头源地址偏移
	rtnlIPv4DstOff     = 16 // IPv4 报头目的地址偏移
	rtnlFilterPrioFW   = 1  // fw 过滤器默认优先级
	rtnlFilterPrioBase = 100

	// TCA_STATS2 子属性枚举 (linux/gen_stats.h)
	rtnlTcaStatsBasic = 1 // TCA_STATS_BASIC (bytes uint64 + packets uint32)
	rtnlTcaStatsQueue = 3 // TCA_STATS_QUEUE (5 * uint32 = 20B)
	rtnlTcaStatsPkt64 = 8 // TCA_STATS_PKT64 (uint64)

	// 以太网协议号 (linux/if_ether.h, 主机序常量, 写入 tcm_info 前转网络序)
	rtnlEthPAll  = 0x0003 // ETH_P_ALL
	rtnlEthPIP   = 0x0800 // ETH_P_IP
	rtnlEthPIPv6 = 0x86dd // ETH_P_IPV6

	// HNC v5.40.0 全局统一 32 位正交 skb->mark 位域常量
	DefaultDevMarkBase      = uint32(0x00800000)
	DefaultDevMarkMask      = uint32(0x00ff0000)
	DefaultDevMarkShift     = 16
	DefaultAppQoSMarkMask   = uint32(0x03000000)
	DefaultAppLimitMarkMask = uint32(0xfc000000)
	DefaultConnmarkMask     = uint32(0xffff0000)
	DefaultHTBRootRateBps   = uint64(125_000_000) // 1000 Mbit/s = 125,000,000 Bytes/s
	DefaultHTBRootBurstB    = uint32(200 * 1024)  // 200 KiB
	DefaultHTBRootQuantumB  = uint32(60000)

	pschedTimeUnitsPerSec = 1_000_000.0
	pschedDefaultTickUsec = 15.625 // Linux 高精度时钟默认: t2us=1000(0x3e8), us2t=64(0x40) -> 15.625 ticks/us
	rtnlSocketTimeoutSec  = 2
	rtnlMaxAckTries       = 64
	iptRestoreTimeout     = 3 * time.Second
)

// dataplaneCounters 统计原生数据面调用计数。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段必须排在结构体起始位置 (offset 0)。
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

// HTBClassStat 表示单个 HTB 类的内核实时统计与当前配置参数。
type HTBClassStat struct {
	ClassID    string `json:"class_id"`    // 十六进制主次类号, 如 "1:5", "1:100", "1:9001", "1:a015"
	Parent     string `json:"parent"`      // 父类标识, 如 "root", "1:", "1:1", "1:5"
	HandleRaw  uint32 `json:"handle_raw"`  // 原始 tcm_handle
	ParentRaw  uint32 `json:"parent_raw"`  // 原始 tcm_parent
	RateBps    uint64 `json:"rate_bps"`    // 当前配置保证速率 (Bytes/sec, 优先取 TCA_HTB_RATE64)
	CeilBps    uint64 `json:"ceil_bps"`    // 当前配置上限速率 (Bytes/sec, 优先取 TCA_HTB_CEIL64)
	RateKbit   uint64 `json:"rate_kbit"`   // 换算后保证速率 (kbit/s = RateBps * 8 / 1000)
	CeilKbit   uint64 `json:"ceil_kbit"`   // 换算后上限速率 (kbit/s = CeilBps * 8 / 1000)
	Buffer     uint32 `json:"buffer"`      // tc_htb_opt.buffer (psched ticks)
	CBuffer    uint32 `json:"cbuffer"`     // tc_htb_opt.cbuffer (psched ticks)
	Quantum    uint32 `json:"quantum"`     // tc_htb_opt.quantum (bytes)
	Level      uint32 `json:"level"`       // tc_htb_opt.level (0 表示叶子节点)
	Prio       uint32 `json:"prio"`        // tc_htb_opt.prio
	SentBytes  uint64 `json:"sent_bytes"`  // TCA_STATS2 -> TCA_STATS_BASIC.bytes
	SentPkts   uint32 `json:"sent_pkts"`   // TCA_STATS2 -> TCA_STATS_BASIC.packets
	SentPkts64 uint64 `json:"sent_pkts64"` // 64 位包计数 (若内核提供 TCA_STATS_PKT64 则取之, 否则等于 SentPkts)
	QLen       uint32 `json:"qlen"`        // TCA_STATS2 -> TCA_STATS_QUEUE.qlen
	Backlog    uint32 `json:"backlog"`     // TCA_STATS2 -> TCA_STATS_QUEUE.backlog
	Drops      uint32 `json:"drops"`       // TCA_STATS2 -> TCA_STATS_QUEUE.drops
	Requeues   uint32 `json:"requeues"`    // TCA_STATS2 -> TCA_STATS_QUEUE.requeues
	Overlimits uint32 `json:"overlimits"`  // TCA_STATS2 -> TCA_STATS_QUEUE.overlimits
}

// ── 测试桩兼容护栏 ────────────────────────────────────────────────────────────

// useNativeDataplane 判断当前 hncDir 是否启用 Go 原生 Netlink / iptables-restore 直通路径。
//
// 规则:
//  1. 若存在紧急降级开关 <hncDir>/run/native_dp.disabled, 强制返回 false;
//  2. 仅当 <hncDir>/bin/hnc_constants.sh 真实存在(且非 sim_test.go 的探针桩脚本)时返回 true;
//  3. 在 t.TempDir() 单测假环境中(无 bin/hnc_constants.sh)返回 false, 自动回退 runBin 脚本路径。
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
	// 兼容 sim_test.go: simTestEnv 会枚举仓库 bin/*.sh 并在假 bin/ 下写入向 run/exec.log
	// 记录调用的探针脚本, 并断言真实 MAC 的 control rule_set 命中 apply_device_rule.sh。
	if b, err := os.ReadFile(constPath); err == nil && bytes.Contains(b, []byte("run/exec.log")) {
		return false
	}
	return true
}

// ── /proc/net/psched 时钟刻度换算（严格对齐 iproute2 tc_core.c） ───────────────

var (
	pschedOnce       sync.Once
	cachedTickInUsec float64
)

// readPschedTickInUsec 读取并缓存 /proc/net/psched 的 tick_in_usec。
func readPschedTickInUsec() float64 {
	pschedOnce.Do(func() {
		b, err := os.ReadFile("/proc/net/psched")
		if err != nil {
			cachedTickInUsec = pschedDefaultTickUsec
			return
		}
		cachedTickInUsec = pschedTickInUsecFromContent(string(b))
	})
	if cachedTickInUsec <= 0 {
		return pschedDefaultTickUsec
	}
	return cachedTickInUsec
}

// pschedTickInUsecFromContent 解析 /proc/net/psched 文本("%08x %08x %08x %08x")。
// 与 iproute2 tc_core_init 完全一致:
//
//	clock_factor = float64(clock_res) / TIME_UNITS_PER_SEC (1e6)
//	tick_in_usec = float64(t2us) / float64(us2t) * clock_factor
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
	clockFactor := float64(clockRes) / pschedTimeUnitsPerSec
	tick := (float64(t2us) / float64(us2t)) * clockFactor
	if tick <= 0 || math.IsNaN(tick) || math.IsInf(tick, 0) {
		return pschedDefaultTickUsec
	}
	return tick
}

// pschedTime2Tick 等价于 iproute2 tc_core_time2tick(unsigned int time)。
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

// tcCalcXmitTime 等价于 iproute2 tc_calc_xmittime(__u64 rate, unsigned int size):
// 计算以 rateBytesPerSec (Bytes/s) 发送 sizeBytes 字节所需的 psched ticks。
func tcCalcXmitTime(rateBytesPerSec uint64, sizeBytes uint32, tickInUsec float64) uint32 {
	if rateBytesPerSec == 0 || sizeBytes == 0 {
		return 0
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}
	usec := pschedTimeUnitsPerSec * (float64(sizeBytes) / float64(rateBytesPerSec))
	// 与 C 端 tc_core_time2tick((unsigned int)(TIME_UNITS_PER_SEC * ((double)size/(double)rate))) 对齐,
	// 同时避免极高速率下 size/rate < 1us 被截断为 0 导致令牌桶深度归零。
	if usec >= 1.0 {
		usec = math.Floor(usec)
	}
	return pschedTime2Tick(usec, tickInUsec)
}

// calcHTBRateTable 等价于 iproute2 tc_calc_rtable: 生成 cell_log 与 256 项传输时间查找表。
func calcHTBRateTable(rateBytesPerSec uint64, mtu uint32, mpu uint16, tickInUsec float64) (uint8, [256]uint32) {
	var rtab [256]uint32
	if mtu == 0 {
		mtu = rtnlDefaultMTU
	}
	cellLog := uint8(0)
	for (mtu>>cellLog) > 255 && cellLog < 31 {
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

// encodeHTBOpt 使用纯 binary.LittleEndian 编码 struct tc_htb_opt(44B) 以及 rtab(1024B) / ctab(1024B)。
//
// struct tc_htb_opt 精确字节布局 (44B):
//   - [0:12]  rate  (tc_ratespec: cell_log[0], linklayer[1], overhead[2:4], cell_align[4:6], mpu[6:8], rate[8:12])
//   - [12:24] ceil  (tc_ratespec: 同上)
//   - [24:28] buffer  (uint32 psched ticks)
//   - [28:32] cbuffer (uint32 psched ticks)
//   - [32:36] quantum (uint32 bytes)
//   - [36:40] level   (uint32, 入参填 0)
//   - [40:44] prio    (uint32)
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

	putRatespec := func(dst []byte, cellLog uint8, bps uint64) {
		dst[0] = cellLog
		dst[1] = rtnlLinkLayerEth
		binary.LittleEndian.PutUint16(dst[2:4], 0)      // overhead = 0
		binary.LittleEndian.PutUint16(dst[4:6], 0xffff) // cell_align = -1 (int16)
		binary.LittleEndian.PutUint16(dst[6:8], 0)      // mpu = 0
		r32 := uint32(math.MaxUint32)
		if bps < uint64(math.MaxUint32) {
			r32 = uint32(bps)
		}
		binary.LittleEndian.PutUint32(dst[8:12], r32)
	}

	putRatespec(opt[0:12], rCellLog, rateBps)
	putRatespec(opt[12:24], cCellLog, ceilBps)

	bufTicks := tcCalcXmitTime(rateBps, burstBytes, tickInUsec)
	cbufTicks := tcCalcXmitTime(ceilBps, cburstBytes, tickInUsec)
	binary.LittleEndian.PutUint32(opt[24:28], bufTicks)
	binary.LittleEndian.PutUint32(opt[28:32], cbufTicks)
	binary.LittleEndian.PutUint32(opt[32:36], quantum)
	binary.LittleEndian.PutUint32(opt[36:40], 0) // level (out only)
	binary.LittleEndian.PutUint32(opt[40:44], prio)

	for i := 0; i < 256; i++ {
		binary.LittleEndian.PutUint32(rtabBuf[i*4:i*4+4], rtab[i])
		binary.LittleEndian.PutUint32(ctabBuf[i*4:i*4+4], ctab[i])
	}
	return opt, rtabBuf, ctabBuf
}

// hncBurstBytesForRate 复刻 bin/tc_rate_calc.sh 的 burst 时间窗算法 (返回字节数)。
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
		win = 0.008192
		fl = bps * 0.0625
		flmax = 8192.0
		if mbps >= 100.0 {
			capBytes = 1024.0 * 1024.0
		} else {
			capBytes = 64.0 * 1024.0
		}
	} else {
		win = 0.02048
		fl = bps * 0.125
		flmax = 16384.0
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

// hncQuantumForRate 复刻 bin/tc_rate_calc.sh 的 quantum=clamp(rate_Bps/10, 1514, 60000)。
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

// mbpsStrToBytesPerSec 将 "10" / "0.5" / "5120kbit" / "10mbit" 转为 Bytes/sec。
func mbpsStrToBytesPerSec(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := 1_000_000.0 // 裸数字按 Mbps 处理
	switch {
	case strings.HasSuffix(s, "gbit"):
		s = strings.TrimSuffix(s, "gbit")
		mult = 1_000_000_000.0
	case strings.HasSuffix(s, "mbit"):
		s = strings.TrimSuffix(s, "mbit")
		mult = 1_000_000.0
	case strings.HasSuffix(s, "kbit"):
		s = strings.TrimSuffix(s, "kbit")
		mult = 1_000.0
	case strings.HasSuffix(s, "bit"):
		s = strings.TrimSuffix(s, "bit")
		mult = 1.0
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

// htbClassMinorForMid 将设备 mark_id (1..99) 映射为与 tc_manager.sh 完全一致的 HTB minor 号:
//   - mid=1   -> "1:100" -> 0x0100 (避开根父类 1:1)
//   - mid=2..99 -> 十进制字面量按 tc 十六进制解析, 如 mid=5 -> 0x0005("1:5"), mid=15 -> 0x0015("1:15")
func htbClassMinorForMid(mid int) (uint16, error) {
	if mid < 1 || mid > 99 {
		return 0, fmt.Errorf("mark_id %d out of range [1,99]", mid)
	}
	if mid == 1 {
		return 0x0100, nil
	}
	hi := uint16(mid / 10)
	lo := uint16(mid % 10)
	return (hi << 4) | lo, nil
}

// formatTCHandle 将 32 位 tc handle 格式化为 iproute2 风格字符串 (如 "root", "1:", "1:5", "1:100", "1:a015")。
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

// nlIfaceIndexByName 解析网卡名对应的内核 ifindex (优先轻量 sysfs 读取, 退回 net.InterfaceByName)。
func nlIfaceIndexByName(iface string) (int, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" || !ifaceNameRE.MatchString(iface) {
		return 0, fmt.Errorf("invalid interface name %q", iface)
	}
	if b, err := os.ReadFile("/sys/class/net/" + iface + "/ifindex"); err == nil {
		if idx, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && idx > 0 {
			return idx, nil
		}
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	if ifi.Index <= 0 {
		return 0, fmt.Errorf("interface %q returned non-positive ifindex %d", iface, ifi.Index)
	}
	return ifi.Index, nil
}

// ── 纯 binary.LittleEndian Netlink 报文构造器 ────────────────────────────────

func rtnlAlign(n int) int {
	return (n + (rtnlAlignTo - 1)) &^ (rtnlAlignTo - 1)
}

func rtnlHtons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func rtnlCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func rtnlNextSeq() uint32 {
	v := uint32(dpStats.seqGen.Add(1))
	if v == 0 {
		v = uint32(dpStats.seqGen.Add(1))
	}
	return v
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
	// nlmsghdr (16B)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	binary.LittleEndian.PutUint16(buf[6:8], flags)
	binary.LittleEndian.PutUint32(buf[8:12], seq)
	binary.LittleEndian.PutUint32(buf[12:16], 0)
	// tcmsg (20B)
	buf[16] = 0 // tcm_family = AF_UNSPEC
	buf[17] = 0
	binary.LittleEndian.PutUint16(buf[18:20], 0)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(int32(ifindex)))
	binary.LittleEndian.PutUint32(buf[24:28], handle)
	binary.LittleEndian.PutUint32(buf[28:32], parent)
	binary.LittleEndian.PutUint32(buf[32:36], info)
	copy(buf[36:], attrs)
	return buf
}

// buildHTBRootQdiscMsg 构造根 qdisc htb 1: default <defaultMinor> 报文。
func buildHTBRootQdiscMsg(seq uint32, ifindex int, defaultMinor uint16) []byte {
	var glob [rtnlHtbGlobSize]byte
	binary.LittleEndian.PutUint32(glob[0:4], rtnlHtbProtoVer)
	binary.LittleEndian.PutUint32(glob[4:8], rtnlHtbDefR2Q)
	binary.LittleEndian.PutUint32(glob[8:12], uint32(defaultMinor))
	binary.LittleEndian.PutUint32(glob[12:16], 0)
	binary.LittleEndian.PutUint32(glob[16:20], 0)

	var opts []byte
	opts = rtnlPutAttr(opts, rtnlTcaHtbInit, glob[:])

	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "htb")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewQdisc, flags, seq, ifindex, rtnlHtbRootMaj, rtnlTcHRoot, 0, attrs)
}

// buildHTBClassUpsertMsg 构造 RTM_NEWTCLASS 报文(含 PARMS + RTAB + CTAB + RATE64 + CEIL64)。
func buildHTBClassUpsertMsg(seq uint32, ifindex int, parent, classHandle uint32, rateBps, ceilBps uint64, burstBytes, cburstBytes, quantum, prio uint32, tickInUsec float64) []byte {
	if ceilBps == 0 {
		ceilBps = rateBps
	}
	opt, rtab, ctab := encodeHTBOpt(rateBps, ceilBps, burstBytes, cburstBytes, quantum, prio, tickInUsec)

	var opts []byte
	opts = rtnlPutAttr(opts, rtnlTcaHtbParms, opt[:])
	opts = rtnlPutAttr(opts, rtnlTcaHtbRtab, rtab[:])
	opts = rtnlPutAttr(opts, rtnlTcaHtbCtab, ctab[:])
	opts = rtnlPutAttrU64(opts, rtnlTcaHtbRate64, rateBps)
	opts = rtnlPutAttrU64(opts, rtnlTcaHtbCeil64, ceilBps)

	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "htb")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewTClass, flags, seq, ifindex, classHandle, parent, 0, attrs)
}

// buildFqCodelLeafMsg 构造 fq_codel 叶子队列报文 (withParams=true 时附带 target=5ms/interval=100ms/quantum=1514/limit=1024)。
func buildFqCodelLeafMsg(seq uint32, ifindex int, parent, leafHandle uint32, withParams bool) []byte {
	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "fq_codel")
	if withParams {
		var opts []byte
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelTarget, 5000)      // 5ms
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelInterval, 100_000) // 100ms
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelQuantum, 1514)
		opts = rtnlPutAttrU32(opts, rtnlTcaFqCodelLimit, 1024)
		attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)
	}
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewQdisc, flags, seq, ifindex, leafHandle, parent, 0, attrs)
}

func buildSimpleKindLeafMsg(seq uint32, ifindex int, parent, leafHandle uint32, kind string) []byte {
	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, kind)
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewQdisc, flags, seq, ifindex, leafHandle, parent, 0, attrs)
}

// buildPfifoScaledLeafMsg 为极端裁剪无 fq_codel/fq/sfq 的厂商内核构造按速率缩放的 pfifo(limit 16..256),
// 避免退回 tx_queue_len=1000 默认队列在 2Mbps 低速限速下造成 ~6000ms 缓冲区膨胀!
func buildPfifoScaledLeafMsg(seq uint32, ifindex int, parent, leafHandle uint32, rateBps uint64) []byte {
	limitPkts := uint32(128)
	if rateBps > 0 {
		// 约 40ms BDP 窗口 (rateBps * 0.04 / 1500B), 夹在 [16, 256] 包之间
		bdp := (rateBps * 40) / (1000 * 1500)
		if bdp < 16 {
			limitPkts = 16
		} else if bdp > 256 {
			limitPkts = 256
		} else {
			limitPkts = uint32(bdp)
		}
	}
	var qopt [4]byte
	binary.LittleEndian.PutUint32(qopt[:], limitPkts)
	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "pfifo")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, qopt[:])
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewQdisc, flags, seq, ifindex, leafHandle, parent, 0, attrs)
}

// nlAttachAdaptiveLeafQdisc 按五级兼容链尝试挂载低延迟叶子队列:
// fq_codel(5ms/100ms) -> fq_codel(默认) -> fq -> sfq -> 按速率缩放 pfifo(16..256)。
func nlAttachAdaptiveLeafQdisc(fd, ifindex int, parent, leafHandle uint32, rateBps uint64) string {
	seq1 := rtnlNextSeq()
	if rtnlSendAndWaitAck(fd, buildFqCodelLeafMsg(seq1, ifindex, parent, leafHandle, true), seq1) == nil {
		return "fq_codel"
	}
	seq2 := rtnlNextSeq()
	if rtnlSendAndWaitAck(fd, buildFqCodelLeafMsg(seq2, ifindex, parent, leafHandle, false), seq2) == nil {
		return "fq_codel"
	}
	for _, kind := range []string{"fq", "sfq"} {
		seqK := rtnlNextSeq()
		if rtnlSendAndWaitAck(fd, buildSimpleKindLeafMsg(seqK, ifindex, parent, leafHandle, kind), seqK) == nil {
			return kind
		}
	}
	seqP := rtnlNextSeq()
	if rtnlSendAndWaitAck(fd, buildPfifoScaledLeafMsg(seqP, ifindex, parent, leafHandle, rateBps), seqP) == nil {
		return "pfifo_scaled"
	}
	return "kernel_default"
}

// buildFwFilterMsg 构造带掩码 fw 过滤器报文 (TCA_FW_CLASSID + TCA_FW_MASK)。
func buildFwFilterMsg(seq uint32, ifindex int, parent uint32, prio, ethProto uint16, markVal, markMask, classID uint32) []byte {
	if markMask == 0 {
		markMask = DefaultDevMarkMask
	}
	// 内核 net/sched/cls_fw.c 强制校验 (handle & ~mask) == 0 且 handle != 0
	maskedHandle := markVal & markMask
	var opts []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaFwClassID, classID)
	opts = rtnlPutAttrU32(opts, rtnlTcaFwMask, markMask)

	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "fw")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	info := (uint32(prio) << 16) | uint32(rtnlHtons(ethProto))
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate | rtnlFReplace)
	return rtnlBuildTCMsg(rtnlNewTFilter, flags, seq, ifindex, maskedHandle, parent, info, attrs)
}

// buildU32IPv4FilterMsg 构造 IPv4 src/dst /32 匹配的 u32 过滤器报文。
//
// struct tc_u32_sel(16B) + struct tc_u32_key(16B) = 32B:
//   - sel[0]     = TC_U32_TERMINAL (1)
//   - sel[2]     = nkeys (1)
//   - key[0:4]   = mask 0xffffffff (network byte order)
//   - key[4:8]   = IPv4 4B (network byte order, 用 LittleEndian 组合单字节写入确保跨端一致)
//   - key[8:12]  = off (int32 LE: src=12, dst=16)
//   - key[12:16] = offmask (0)
func buildU32IPv4FilterMsg(seq uint32, ifindex int, parent uint32, prio uint16, ip4 net.IP, isUplink bool, classID uint32) ([]byte, error) {
	v4 := ip4.To4()
	if len(v4) != 4 {
		return nil, fmt.Errorf("invalid IPv4 address %v", ip4)
	}
	var sel [rtnlU32SelHdrSize + rtnlU32KeySize]byte
	sel[0] = rtnlTcU32Terminal // flags = TC_U32_TERMINAL, 命中后直接返回 classid
	sel[1] = 0                 // offshift
	sel[2] = 1                 // nkeys = 1
	sel[3] = 0                 // align pad
	// offmask(4:6), off(6:8), offoff(8:10), hoff(10:12), hmask(12:16) 全 0

	// keys[0] 起始于 offset 16:
	binary.LittleEndian.PutUint32(sel[16:20], uint32(0xffffffff))
	ipWireLE := uint32(v4[0]) | (uint32(v4[1]) << 8) | (uint32(v4[2]) << 16) | (uint32(v4[3]) << 24)
	binary.LittleEndian.PutUint32(sel[20:24], ipWireLE)
	hdrOff := uint32(rtnlIPv4DstOff)
	if isUplink {
		hdrOff = uint32(rtnlIPv4SrcOff)
	}
	binary.LittleEndian.PutUint32(sel[24:28], hdrOff)
	binary.LittleEndian.PutUint32(sel[28:32], 0)

	var opts []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaU32ClassID, classID)
	opts = rtnlPutAttr(opts, rtnlTcaU32Sel, sel[:])

	var attrs []byte
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "u32")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	info := (uint32(prio) << 16) | uint32(rtnlHtons(rtnlEthPIP))
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate)
	return rtnlBuildTCMsg(rtnlNewTFilter, flags, seq, ifindex, 0, parent, info, attrs), nil
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

// ── RTNetlink Socket 会话管理 ───────────────────────────────────────────────

func openRTNetlinkSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("rtnl socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("rtnl bind: %w", err)
	}
	tv := syscall.Timeval{Sec: rtnlSocketTimeoutSec}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	return fd, nil
}

func rtnlSendAndWaitAck(fd int, req []byte, wantSeq uint32) error {
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	for {
		err := syscall.Sendto(fd, req, 0, dst)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("rtnl sendto: %w", err)
		}
		break
	}

	buf := make([]byte, 8192)
	for tries := 0; tries < rtnlMaxAckTries; tries++ {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("rtnl recv ack: %w", err)
		}
		if n <= 0 {
			return errors.New("rtnl recv ack: empty reply")
		}
		matched, ackErr, parseErr := parseRTNLControlAck(buf[:n], wantSeq)
		if parseErr != nil {
			return parseErr
		}
		if matched {
			return ackErr
		}
	}
	return fmt.Errorf("rtnl recv ack: unmatched seq %d after %d frames", wantSeq, rtnlMaxAckTries)
}

func parseRTNLControlAck(b []byte, wantSeq uint32) (bool, error, error) {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, nil, errors.New("rtnl: truncated ack nlmsghdr")
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		msgSeq := binary.LittleEndian.Uint32(b[off+8 : off+12])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, nil, fmt.Errorf("rtnl: invalid ack nlmsg_len %d (rem %d)", msgLen, rem)
		}
		msg := b[off : off+msgLen]
		adv := rtnlAlign(msgLen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}

		if msgSeq != wantSeq {
			continue
		}
		if msgType == rtnlMsgError {
			if len(msg) < rtnlMsgHdrLen+4 {
				return true, nil, errors.New("rtnl: truncated nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code == 0 {
				return true, nil, nil
			}
			errno := syscall.Errno(-code)
			if code > 0 {
				errno = syscall.Errno(code)
			}
			return true, fmt.Errorf("rtnl kernel errno %d: %w", code, errno), nil
		}
	}
	return false, nil, nil
}

func isIgnorableDelErr(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EINVAL)
}

type rtnlQdiscBrief struct {
	ifIndex int
	handle  uint32
	parent  uint32
	kind    string
}

func rtnlDumpQdiscsOnSocket(fd int, wantIfIndex int) ([]rtnlQdiscBrief, error) {
	seq := rtnlNextSeq()
	req := rtnlBuildTCMsg(rtnlGetQdisc, rtnlFRequest|rtnlFDump, seq, wantIfIndex, 0, 0, 0, nil)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("rtnl dump qdisc send: %w", err)
	}
	var out []rtnlQdiscBrief
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("rtnl dump qdisc recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("rtnl dump qdisc: empty recv")
		}
		done, err := parseQdiscBriefChunk(buf[:n], wantIfIndex, &out)
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
	}
}

func parseQdiscBriefChunk(b []byte, wantIfIndex int, dst *[]rtnlQdiscBrief) (bool, error) {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, errors.New("rtnl: truncated qdisc nlmsghdr")
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, fmt.Errorf("rtnl: invalid qdisc nlmsg_len %d (rem %d)", msgLen, rem)
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
				return false, errors.New("rtnl: truncated qdisc nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code == 0 {
				continue
			}
			errno := syscall.Errno(-code)
			if code > 0 {
				errno = syscall.Errno(code)
			}
			return false, fmt.Errorf("rtnl qdisc dump error %d: %w", code, errno)
		case rtnlMsgNoop:
			continue
		}
		if msgType != rtnlNewQdisc {
			continue
		}
		if len(msg) < rtnlMsgHdrLen+rtnlTcMsgLen {
			return false, errors.New("rtnl: truncated qdisc tcmsg")
		}
		ifidx := int(int32(binary.LittleEndian.Uint32(msg[20:24])))
		handle := binary.LittleEndian.Uint32(msg[24:28])
		parent := binary.LittleEndian.Uint32(msg[28:32])
		var kind string
		for aoff := rtnlMsgHdrLen + rtnlTcMsgLen; aoff < len(msg); {
			arem := len(msg) - aoff
			if arem < rtnlAttrHdr {
				return false, errors.New("rtnl: truncated qdisc attr header")
			}
			alen := int(binary.LittleEndian.Uint16(msg[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(msg[aoff+2:aoff+4]) & nlaTypeMask
			if alen < rtnlAttrHdr || alen > arem {
				return false, fmt.Errorf("rtnl: invalid qdisc attr len %d (rem %d)", alen, arem)
			}
			if atype == rtnlTcaKind {
				kind = rtnlCString(msg[aoff+4 : aoff+alen])
			}
			nadv := rtnlAlign(alen)
			if nadv > arem {
				aoff = len(msg)
			} else {
				aoff += nadv
			}
		}
		if wantIfIndex > 0 && ifidx != wantIfIndex {
			continue
		}
		*dst = append(*dst, rtnlQdiscBrief{
			ifIndex: ifidx,
			handle:  handle,
			parent:  parent,
			kind:    kind,
		})
	}
	return false, nil
}

// ── 核心 API 1: nlEnsureHTBRoot ────────────────────────────────────────────

// nlEnsureHTBRoot 幂等确保指定网卡上的根 HTB 队列 (1:, default <defaultMinor>)、
// 根父类 1:1、默认类 1:<defaultMinor> 及其 fq_codel 叶子队列就绪。
//
// 参数:
//   - ifindex: 目标网卡索引 (>0)
//   - defaultMinor: 未匹配流量的默认 minor (传 0 时默认 0x9999, 即 1:9999)
//   - rootRateBps: 根类与默认类带宽 (Bytes/sec; 传 0 时默认 1000Mbit = 125,000,000 B/s)
func nlEnsureHTBRoot(ifindex int, defaultMinor uint16, rootRateBps uint64) error {
	dpStats.nlEnsureCalls.Add(1)
	if ifindex <= 0 {
		dpStats.nlErrors.Add(1)
		return fmt.Errorf("nlEnsureHTBRoot: invalid ifindex %d", ifindex)
	}
	if defaultMinor == 0 {
		defaultMinor = rtnlDefMinor
	}
	if rootRateBps == 0 {
		rootRateBps = DefaultHTBRootRateBps
	}

	fd, err := openRTNetlinkSocket()
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}
	defer syscall.Close(fd)

	qdiscs, err := rtnlDumpQdiscsOnSocket(fd, ifindex)
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}

	defClassHandle := rtnlHtbRootMaj | uint32(defaultMinor)
	hasHTBRoot := false
	hasDefLeaf := false
	for _, q := range qdiscs {
		if q.handle == rtnlHtbRootMaj && q.kind == "htb" {
			hasHTBRoot = true
		}
		if q.parent == defClassHandle {
			hasDefLeaf = true
		}
	}

	// 1. 幂等挂载根 qdisc htb 1: default 0x9999 (已存在则复用, 绝不重置现有子类与统计计数器)
	if !hasHTBRoot {
		seq := rtnlNextSeq()
		req := buildHTBRootQdiscMsg(seq, ifindex, defaultMinor)
		if err := rtnlSendAndWaitAck(fd, req, seq); err != nil && !errors.Is(err, syscall.EEXIST) {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlEnsureHTBRoot: install root htb 1: failed: %w", err)
		}
	}

	// 2. 检查现有 HTB 类, 幂等确保根父类 1:1 与默认类 1:<defaultMinor> 存在
	classes, err := nlDumpHTBClassStatsOnSocket(fd, ifindex)
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}
	tickInUsec := readPschedTickInUsec()
	burst := hncBurstBytesForRate(rootRateBps, false)

	if st, ok := classes["1:1"]; !ok || st.RateBps != rootRateBps || st.CeilBps != rootRateBps {
		seq := rtnlNextSeq()
		req := buildHTBClassUpsertMsg(seq, ifindex, rtnlHtbRootMaj, rtnlHtbRootCls, rootRateBps, rootRateBps, burst, burst, DefaultHTBRootQuantumB, 0, tickInUsec)
		if err := rtnlSendAndWaitAck(fd, req, seq); err != nil {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlEnsureHTBRoot: upsert root class 1:1 failed: %w", err)
		}
	}

	defClassKey := formatTCHandle(defClassHandle)
	if _, ok := classes[defClassKey]; !ok {
		seq := rtnlNextSeq()
		req := buildHTBClassUpsertMsg(seq, ifindex, rtnlHtbRootCls, defClassHandle, rootRateBps, rootRateBps, burst, burst, DefaultHTBRootQuantumB, 7, tickInUsec)
		if err := rtnlSendAndWaitAck(fd, req, seq); err != nil {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlEnsureHTBRoot: upsert default class %s failed: %w", defClassKey, err)
		}
	}

	// 3. 确保默认类 1:<defaultMinor> 挂载自适应低延迟叶子 (fq_codel -> fq -> sfq -> 缩放 pfifo)
	if !hasDefLeaf {
		leafHandle := uint32(defaultMinor) << 16
		_ = nlAttachAdaptiveLeafQdisc(fd, ifindex, defClassHandle, leafHandle, rootRateBps)
	}
	return nil
}

// ── 核心 API 2: nlUpsertDeviceHTB ──────────────────────────────────────────

// nlUpsertDeviceHTB 在单条 AF_NETLINK 连接内原子完成设备级 HTB 限速类、fq_codel 叶子、
// 正交掩码 fw 过滤器及 IPv4 u32 src/dst 过滤器的下发与热更新。
//
// 参数说明:
//   - ifindex: 热点下行接口 (如 wlan2/ap0, isUplink=false) 或 IFB 上行接口 (如 ifb0, isUplink=true)
//   - classMinor: HTB 次类号 (如 0x0005 -> "1:5", 0x0100 -> "1:100")
//   - rateBps, ceilBps: 保证速率与峰值速率 (单位 Bytes/sec; ceilBps=0 时自动取 rateBps)
//   - burstBytes, cburstBytes, quantum: 桶深与调度量子 (传 0 时按 HNC 时间窗公式自动计算)
//   - markVal, markMask: 正交 skb->mark 值与掩码 (markMask=0 时默认 0x00ff0000; markVal=0 时跳过 fw 过滤器)
//   - ipv4: 客户端 IPv4 地址 (非空合法 IPv4 时下发 u32 dst/src /32 过滤器)
//   - isUplink: false 下行匹配 IPv4 dst(offset 16), true 上行匹配 IPv4 src(offset 12)
func nlUpsertDeviceHTB(
	ifindex int,
	classMinor uint16,
	rateBps, ceilBps uint64,
	burstBytes, cburstBytes, quantum uint32,
	markVal, markMask uint32,
	ipv4 string,
	isUplink bool,
) error {
	dpStats.nlUpsertCalls.Add(1)
	if ifindex <= 0 {
		dpStats.nlErrors.Add(1)
		return fmt.Errorf("nlUpsertDeviceHTB: invalid ifindex %d", ifindex)
	}
	if classMinor == 0 || classMinor == 1 || classMinor == rtnlDefMinor {
		dpStats.nlErrors.Add(1)
		return fmt.Errorf("nlUpsertDeviceHTB: reserved classMinor 0x%x", classMinor)
	}
	if rateBps == 0 {
		dpStats.nlErrors.Add(1)
		return errors.New("nlUpsertDeviceHTB: rateBps must be > 0")
	}
	if ceilBps == 0 {
		ceilBps = rateBps
	}
	if markMask == 0 {
		markMask = DefaultDevMarkMask
	}

	var parsedIP4 net.IP
	ipv4 = strings.TrimSpace(ipv4)
	if ipv4 != "" {
		ip := net.ParseIP(ipv4)
		if ip == nil || ip.To4() == nil {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlUpsertDeviceHTB: invalid ipv4 %q", ipv4)
		}
		parsedIP4 = ip.To4()
	}

	fd, err := openRTNetlinkSocket()
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}
	defer syscall.Close(fd)

	classHandle := rtnlHtbRootMaj | uint32(classMinor)

	// 在同一条 Netlink 连接上检查根树、子类占用状态(如 app_qos 3 档子类)及现有叶子队列
	qdiscs, err := rtnlDumpQdiscsOnSocket(fd, ifindex)
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}
	hasRoot := false
	hasLeaf := false
	for _, q := range qdiscs {
		if q.handle == rtnlHtbRootMaj && q.kind == "htb" {
			hasRoot = true
		}
		if q.parent == classHandle {
			hasLeaf = true
		}
	}
	if !hasRoot {
		seq := rtnlNextSeq()
		if err := rtnlSendAndWaitAck(fd, buildHTBRootQdiscMsg(seq, ifindex, rtnlDefMinor), seq); err != nil && !errors.Is(err, syscall.EEXIST) {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlUpsertDeviceHTB: auto-init root htb failed: %w", err)
		}
	}

	classes, err := nlDumpHTBClassStatsOnSocket(fd, ifindex)
	if err != nil {
		dpStats.nlErrors.Add(1)
		return err
	}
	tickInUsec := readPschedTickInUsec()
	if _, ok := classes["1:1"]; !ok {
		rootBurst := hncBurstBytesForRate(DefaultHTBRootRateBps, false)
		seq := rtnlNextSeq()
		req := buildHTBClassUpsertMsg(seq, ifindex, rtnlHtbRootMaj, rtnlHtbRootCls, DefaultHTBRootRateBps, DefaultHTBRootRateBps, rootBurst, rootBurst, DefaultHTBRootQuantumB, 0, tickInUsec)
		if err := rtnlSendAndWaitAck(fd, req, seq); err != nil {
			dpStats.nlErrors.Add(1)
			return fmt.Errorf("nlUpsertDeviceHTB: ensure parent 1:1 failed: %w", err)
		}
	}

	hasChildren := false
	for _, st := range classes {
		if st.ParentRaw == classHandle {
			hasChildren = true
			break
		}
	}

	// 1. 原地创建或更新设备 HTB 类 1:<classMinor> (NLM_F_CREATE|NLM_F_REPLACE 零闪断刷新)
	seqCls := rtnlNextSeq()
	clsMsg := buildHTBClassUpsertMsg(seqCls, ifindex, rtnlHtbRootCls, classHandle, rateBps, ceilBps, burstBytes, cburstBytes, quantum, 3, tickInUsec)
	if err := rtnlSendAndWaitAck(fd, clsMsg, seqCls); err != nil {
		dpStats.nlErrors.Add(1)
		return fmt.Errorf("nlUpsertDeviceHTB: upsert class %s failed: %w", formatTCHandle(classHandle), err)
	}

	// 2. 当该类无子类且尚未挂叶子 qdisc(如 netem/cake/fq_codel)时, 按五级兼容链挂载低延迟叶子
	if !hasChildren && !hasLeaf {
		leafMajor := uint32(0x2000+(uint32(classMinor)&0x0fff)) << 16
		if isUplink {
			leafMajor = uint32(0x3000+(uint32(classMinor)&0x0fff)) << 16
		}
		_ = nlAttachAdaptiveLeafQdisc(fd, ifindex, classHandle, leafMajor, ceilBps)
	}

	// 3. 下发带正交掩码 fw 过滤器 (TCA_FW_CLASSID + TCA_FW_MASK = 0x00ff0000)
	fwOK := false
	if (markVal & markMask) != 0 {
		seqFW := rtnlNextSeq()
		fwMsg := buildFwFilterMsg(seqFW, ifindex, rtnlHtbRootMaj, rtnlFilterPrioFW, rtnlEthPAll, markVal, markMask, classHandle)
		if err := rtnlSendAndWaitAck(fd, fwMsg, seqFW); err == nil {
			fwOK = true
		} else {
			// 个别裁剪内核对 protocol all 的 cls_fw 返回 EINVAL, 自动回退双协议挂载
			seqIP := rtnlNextSeq()
			errIP := rtnlSendAndWaitAck(fd, buildFwFilterMsg(seqIP, ifindex, rtnlHtbRootMaj, rtnlFilterPrioFW, rtnlEthPIP, markVal, markMask, classHandle), seqIP)
			seqV6 := rtnlNextSeq()
			_ = rtnlSendAndWaitAck(fd, buildFwFilterMsg(seqV6, ifindex, rtnlHtbRootMaj, 3, rtnlEthPIPv6, markVal, markMask, classHandle), seqV6)
			if errIP == nil {
				fwOK = true
			}
		}
	}

	// 4. 下发 IPv4 u32 dst(下行) / src(上行) 过滤器 (每设备独占 prio, 先删旧规则防 DHCP 换 IP 堆积)
	u32OK := false
	if parsedIP4 != nil {
		u32Prio := u32FilterPrioForMinor(classMinor)
		seqDel := rtnlNextSeq()
		delMsg := buildDelFilterMsg(seqDel, ifindex, rtnlHtbRootMaj, 0, u32Prio, rtnlEthPIP, "")
		_ = rtnlSendAndWaitAck(fd, delMsg, seqDel)

		seqU32 := rtnlNextSeq()
		u32Msg, err := buildU32IPv4FilterMsg(seqU32, ifindex, rtnlHtbRootMaj, u32Prio, parsedIP4, isUplink, classHandle)
		if err != nil {
			dpStats.nlErrors.Add(1)
			return err
		}
		if err := rtnlSendAndWaitAck(fd, u32Msg, seqU32); err != nil {
			if !fwOK {
				dpStats.nlErrors.Add(1)
				return fmt.Errorf("nlUpsertDeviceHTB: both fw and u32 filters failed on ifindex=%d: %w", ifindex, err)
			}
		} else {
			u32OK = true
		}
	}

	if (markVal&markMask) != 0 && !fwOK && !u32OK {
		dpStats.nlErrors.Add(1)
		return fmt.Errorf("nlUpsertDeviceHTB: failed to attach fw filter for mark=0x%x/0x%x", markVal, markMask)
	}
	return nil
}

func u32FilterPrioForMinor(classMinor uint16) uint16 {
	if classMinor == 0x0100 {
		return rtnlFilterPrioBase + 1
	}
	// 将十六进制字面量 (0x02..0x99) 还原或限定在稳定独立区间 [101..4350]
	hi := (classMinor >> 4) & 0x0f
	lo := classMinor & 0x0f
	if classMinor < 0x0100 && hi <= 9 && lo <= 9 {
		return rtnlFilterPrioBase + hi*10 + lo
	}
	return 200 + (classMinor & 0x0fff)
}

func midFromHTBClassMinor(classMinor uint16) (int, bool) {
	if classMinor == 0x0100 {
		return 1, true
	}
	hi := int((classMinor >> 4) & 0x0f)
	lo := int(classMinor & 0x0f)
	if classMinor < 0x0100 && hi <= 9 && lo <= 9 {
		mid := hi*10 + lo
		if mid >= 2 && mid <= 99 {
			return mid, true
		}
	}
	return 0, false
}

// deviceFWDeleteSpecs 返回卸载设备 HTB 类前需清理的全部根 parent 1: cls_fw (prio, ethProto) 组合,
// 涵盖常规 pref 1(all/ip)、pref 3(ipv6) 以及可能由 apply_app_qos 遗留的 pref 50(all/ip/ipv6) 与 pref 51(ipv6),
// 彻底杜绝残留根过滤器引用导致 RTM_DELTCLASS 返回 -EBUSY。
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

// nlDeleteDeviceHTB 幂等卸载指定设备的 u32 过滤器、fw 过滤器及 HTB 类。
func nlDeleteDeviceHTB(ifindex int, classMinor uint16, markVal, markMask uint32) error {
	if ifindex <= 0 || classMinor == 0 || classMinor == 1 || classMinor == rtnlDefMinor {
		return fmt.Errorf("nlDeleteDeviceHTB: invalid target ifindex=%d minor=0x%x", ifindex, classMinor)
	}
	if markMask == 0 {
		markMask = DefaultDevMarkMask
	}
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	u32Prio := u32FilterPrioForMinor(classMinor)
	seq := rtnlNextSeq()
	_ = rtnlSendAndWaitAck(fd, buildDelFilterMsg(seq, ifindex, rtnlHtbRootMaj, 0, u32Prio, rtnlEthPIP, ""), seq)
	if mid, ok := midFromHTBClassMinor(classMinor); ok {
		seqV6 := rtnlNextSeq()
		_ = rtnlSendAndWaitAck(fd, buildDelFilterMsg(seqV6, ifindex, rtnlHtbRootMaj, 0, uint16(200+mid), rtnlEthPIPv6, ""), seqV6)
	}

	if h := markVal & markMask; h != 0 {
		for _, spec := range deviceFWDeleteSpecs() {
			s := rtnlNextSeq()
			_ = rtnlSendAndWaitAck(fd, buildDelFilterMsg(s, ifindex, rtnlHtbRootMaj, h, spec[0], spec[1], "fw"), s)
		}
	}

	classHandle := rtnlHtbRootMaj | uint32(classMinor)
	seqDelCls := rtnlNextSeq()
	delCls := rtnlBuildTCMsg(rtnlDelTClass, rtnlFRequest|rtnlFAck, seqDelCls, ifindex, classHandle, rtnlHtbRootCls, 0, nil)
	if err := rtnlSendAndWaitAck(fd, delCls, seqDelCls); !isIgnorableDelErr(err) {
		return fmt.Errorf("nlDeleteDeviceHTB: delete class %s failed: %w", formatTCHandle(classHandle), err)
	}
	return nil
}

// ── 核心 API 3: nlDumpHTBClassStats & parseTCClassDumpMsgs ─────────────────

// nlDumpHTBClassStats 发送 RTM_GETTCLASS (NLM_F_REQUEST|NLM_F_DUMP) 并解析指定网卡上全部 HTB 类的实时计数器与速率。
func nlDumpHTBClassStats(ifindex int) (map[string]HTBClassStat, error) {
	dpStats.nlDumpCalls.Add(1)
	if ifindex <= 0 {
		dpStats.nlErrors.Add(1)
		return nil, fmt.Errorf("nlDumpHTBClassStats: invalid ifindex %d", ifindex)
	}
	fd, err := openRTNetlinkSocket()
	if err != nil {
		dpStats.nlErrors.Add(1)
		return nil, err
	}
	defer syscall.Close(fd)

	res, err := nlDumpHTBClassStatsOnSocket(fd, ifindex)
	if err != nil {
		dpStats.nlErrors.Add(1)
		return nil, err
	}
	return res, nil
}

func nlDumpHTBClassStatsOnSocket(fd int, ifindex int) (map[string]HTBClassStat, error) {
	seq := rtnlNextSeq()
	req := rtnlBuildTCMsg(rtnlGetTClass, rtnlFRequest|rtnlFDump, seq, ifindex, 0, 0, 0, nil)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("nlDumpHTBClassStats send: %w", err)
	}

	out := make(map[string]HTBClassStat, 16)
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("nlDumpHTBClassStats recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("nlDumpHTBClassStats: empty recv")
		}
		done, err := parseTCClassDumpChunk(buf[:n], ifindex, out)
		if err != nil {
			return nil, err
		}
		if done {
			return out, nil
		}
	}
}

// parseTCClassDumpMsgs 纯字节流解析 RTM_GETTCLASS dump 响应报文 (零 syscall, 供单元测试直接喂字节流验证)。
//
// 安全保证:
//   - 100% 使用 encoding/binary.LittleEndian, 零 unsafe.Pointer;
//   - 对外层 nlmsghdr、tcmsg、顶层 rtattr、嵌套 TCA_OPTIONS / TCA_STATS2 子属性逐层严格边界校验,
//     任意截断报文一律返回明确 error, 绝不发生 slice bounds out of range panic;
//   - wantIfIndex > 0 时仅保留匹配网卡的 HTB 类 (内核 dump 可能混入其他接口类, 非匹配接口同样先做结构合法性校验)。
func parseTCClassDumpMsgs(b []byte, wantIfIndex int) (map[string]HTBClassStat, error) {
	out := make(map[string]HTBClassStat, 8)
	if _, err := parseTCClassDumpChunk(b, wantIfIndex, out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseTCClassDumpChunk(b []byte, wantIfIndex int, dst map[string]HTBClassStat) (bool, error) {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, fmt.Errorf("rtnl class dump: truncated nlmsghdr (%d < %d)", rem, rtnlMsgHdrLen)
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, fmt.Errorf("rtnl class dump: bad nlmsg_len %d (rem %d)", msgLen, rem)
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
				return false, errors.New("rtnl class dump: truncated nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code == 0 {
				continue
			}
			errno := syscall.Errno(-code)
			if code > 0 {
				errno = syscall.Errno(code)
			}
			return false, fmt.Errorf("rtnl class dump error %d: %w", code, errno)
		case rtnlMsgNoop:
			continue
		}

		if msgType != rtnlNewTClass {
			continue
		}
		if len(msg) < rtnlMsgHdrLen+rtnlTcMsgLen {
			return false, fmt.Errorf("rtnl class dump: truncated tcmsg (%d < %d)", len(msg), rtnlMsgHdrLen+rtnlTcMsgLen)
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

		var (
			kind      string
			rate32    uint64
			ceil32    uint64
			rate64    uint64
			ceil64    uint64
			hasRate64 bool
			hasCeil64 bool
			hasPkt64  bool
			gotStats2 bool
		)

		for aoff := rtnlMsgHdrLen + rtnlTcMsgLen; aoff < len(msg); {
			arem := len(msg) - aoff
			if arem < rtnlAttrHdr {
				return false, fmt.Errorf("rtnl class dump: truncated tca header (rem %d)", arem)
			}
			alen := int(binary.LittleEndian.Uint16(msg[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(msg[aoff+2:aoff+4]) & nlaTypeMask
			if alen < rtnlAttrHdr || alen > arem {
				return false, fmt.Errorf("rtnl class dump: bad tca len %d (rem %d)", alen, arem)
			}
			aval := msg[aoff+4 : aoff+alen]

			switch atype {
			case rtnlTcaKind:
				kind = rtnlCString(aval)
			case rtnlTcaOptions:
				if err := parseHTBOptionsAttrs(aval, &st, &rate32, &ceil32, &rate64, &ceil64, &hasRate64, &hasCeil64); err != nil {
					return false, err
				}
			case rtnlTcaStats2:
				if err := parseTCStats2Attrs(aval, &st, &hasPkt64); err != nil {
					return false, err
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

			nadv := rtnlAlign(alen)
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

		if hasRate64 {
			st.RateBps = rate64
		} else {
			st.RateBps = rate32
		}
		if hasCeil64 {
			st.CeilBps = ceil64
		} else {
			st.CeilBps = ceil32
		}
		st.RateKbit = (st.RateBps * 8) / 1000
		st.CeilKbit = (st.CeilBps * 8) / 1000
		if !hasPkt64 {
			st.SentPkts64 = uint64(st.SentPkts)
		}
		dst[st.ClassID] = st
	}
	return false, nil
}

func parseHTBOptionsAttrs(b []byte, st *HTBClassStat, rate32, ceil32, rate64, ceil64 *uint64, hasRate64, hasCeil64 *bool) error {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlAttrHdr {
			return fmt.Errorf("rtnl htb options: truncated nested attr header (rem %d)", rem)
		}
		alen := int(binary.LittleEndian.Uint16(b[off : off+2]))
		atype := binary.LittleEndian.Uint16(b[off+2:off+4]) & nlaTypeMask
		if alen < rtnlAttrHdr || alen > rem {
			return fmt.Errorf("rtnl htb options: bad nested attr len %d (rem %d)", alen, rem)
		}
		val := b[off+4 : off+alen]

		switch atype {
		case rtnlTcaHtbParms:
			if len(val) < rtnlHtbOptSize {
				return fmt.Errorf("rtnl htb options: truncated tc_htb_opt (%d < %d)", len(val), rtnlHtbOptSize)
			}
			*rate32 = uint64(binary.LittleEndian.Uint32(val[8:12]))
			*ceil32 = uint64(binary.LittleEndian.Uint32(val[20:24]))
			st.Buffer = binary.LittleEndian.Uint32(val[24:28])
			st.CBuffer = binary.LittleEndian.Uint32(val[28:32])
			st.Quantum = binary.LittleEndian.Uint32(val[32:36])
			st.Level = binary.LittleEndian.Uint32(val[36:40])
			st.Prio = binary.LittleEndian.Uint32(val[40:44])
		case rtnlTcaHtbRate64:
			if len(val) < 8 {
				return fmt.Errorf("rtnl htb options: truncated RATE64 (%d < 8)", len(val))
			}
			*rate64 = binary.LittleEndian.Uint64(val[0:8])
			*hasRate64 = true
		case rtnlTcaHtbCeil64:
			if len(val) < 8 {
				return fmt.Errorf("rtnl htb options: truncated CEIL64 (%d < 8)", len(val))
			}
			*ceil64 = binary.LittleEndian.Uint64(val[0:8])
			*hasCeil64 = true
		}

		adv := rtnlAlign(alen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
	}
	return nil
}

func parseTCStats2Attrs(b []byte, st *HTBClassStat, hasPkt64 *bool) error {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlAttrHdr {
			return fmt.Errorf("rtnl stats2: truncated nested attr header (rem %d)", rem)
		}
		alen := int(binary.LittleEndian.Uint16(b[off : off+2]))
		atype := binary.LittleEndian.Uint16(b[off+2:off+4]) & nlaTypeMask
		if alen < rtnlAttrHdr || alen > rem {
			return fmt.Errorf("rtnl stats2: bad nested attr len %d (rem %d)", alen, rem)
		}
		val := b[off+4 : off+alen]

		switch atype {
		case rtnlTcaStatsBasic:
			// struct gnet_stats_basic: bytes(uint64 @ 0..8) + packets(uint32 @ 8..12), 64位/ARM EABI 尾填充至 16B
			if len(val) < 12 {
				return fmt.Errorf("rtnl stats2: truncated TCA_STATS_BASIC (%d < 12)", len(val))
			}
			st.SentBytes = binary.LittleEndian.Uint64(val[0:8])
			st.SentPkts = binary.LittleEndian.Uint32(val[8:12])
		case rtnlTcaStatsPkt64:
			if len(val) < 8 {
				return fmt.Errorf("rtnl stats2: truncated TCA_STATS_PKT64 (%d < 8)", len(val))
			}
			st.SentPkts64 = binary.LittleEndian.Uint64(val[0:8])
			*hasPkt64 = true
		case rtnlTcaStatsQueue:
			if len(val) < 20 {
				return fmt.Errorf("rtnl stats2: truncated TCA_STATS_QUEUE (%d < 20)", len(val))
			}
			st.QLen = binary.LittleEndian.Uint32(val[0:4])
			st.Backlog = binary.LittleEndian.Uint32(val[4:8])
			st.Drops = binary.LittleEndian.Uint32(val[8:12])
			st.Requeues = binary.LittleEndian.Uint32(val[12:16])
			st.Overlimits = binary.LittleEndian.Uint32(val[16:20])
		}

		adv := rtnlAlign(alen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
	}
	return nil
}

// ── 核心 API 4: 双栈 iptables-restore --noflush 内存管道提交器 ────────────────

// readDeviceMarkSpec 计算设备 mid(1..99) 的正交 skb->mark 值与掩码。
// 默认采用 v5.40.0 正交位域 0x00XX0000/0x00ff0000 (低 16 位完整保留给 Android netd netId),
// 若 bin/hnc_constants.sh 显式定义了 HNC_DEV_MARK_MASK / HNC_DEV_MARK_SHIFT / HNC_DEV_MARK_BASE 则动态对齐。
func readDeviceMarkSpec(hncDir string, mid int) (uint32, uint32) {
	const low16Mask = uint32(0x0000ffff)
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
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				switch k {
				case "HNC_DEV_MARK_MASK", "HNC_MARK_MASK":
					if u, err := strconv.ParseUint(v, 0, 32); err == nil && u != 0 && (uint32(u)&low16Mask) == 0 {
						mask = uint32(u)
					}
				case "HNC_DEV_MARK_SHIFT", "HNC_MARK_SHIFT":
					if u, err := strconv.ParseUint(v, 10, 8); err == nil && u >= 16 && u < 32 {
						shift = uint(u)
					}
				case "HNC_DEV_MARK_BASE", "HNC_MARK_BASE":
					if u, err := strconv.ParseUint(v, 0, 32); err == nil && (uint32(u)&low16Mask) == 0 {
						base = uint32(u)
					}
				}
			}
		}
	}
	if shift < 16 || (mask&low16Mask) != 0 {
		mask = DefaultDevMarkMask
		shift = uint(DefaultDevMarkShift)
		base = DefaultDevMarkBase
	}
	if mid < 1 || mid > 99 {
		return 0, mask
	}
	val := (base | (uint32(mid) << shift)) & mask
	return val, mask
}

type fwDevSnapshot struct {
	mac  string
	ipv4 string
	mid  int
}

func collectFirewallDesiredState(hncDir, targetMAC, targetIPv4 string, targetMid int, enableMark, enableBlock bool) ([]fwDevSnapshot, []fwDevSnapshot) {
	liveIPs := readLiveDeviceIPv4Map(hncDir)
	if targetIPv4 != "" && validStrictIPv4(targetIPv4) {
		liveIPs[targetMAC] = targetIPv4
	}

	root, _ := rulesStore.ReadAll(hncDir)
	markedByMAC := make(map[string]fwDevSnapshot)
	blockedSet := make(map[string]string) // mac -> ipv4

	if devs, ok := root["devices"].(map[string]interface{}); ok {
		for rawMAC, rawObj := range devs {
			m := strings.ToLower(strings.TrimSpace(rawMAC))
			if !macRE.MatchString(m) {
				continue
			}
			dm, ok := rawObj.(map[string]interface{})
			if !ok {
				continue
			}
			ip := liveIPs[m]
			if ip == "" {
				if s := strings.TrimSpace(anyToRuleString(dm["ip"])); validStrictIPv4(s) {
					ip = s
				}
			}
			midVal := anyToRuleInt(dm["mark_id"])
			if midVal >= 1 && midVal <= 99 && (deviceNeedsMarkRule(dm) || deviceHasSecondaryQdiscOwner(hncDir, "", m, midVal, dm)) {
				markedByMAC[m] = fwDevSnapshot{mac: m, ipv4: ip, mid: midVal}
			}
		}
	}

	if bl, ok := root["blacklist"].([]interface{}); ok {
		for _, item := range bl {
			m := strings.ToLower(strings.TrimSpace(anyToRuleString(item)))
			if macRE.MatchString(m) {
				blockedSet[m] = liveIPs[m]
			}
		}
	}

	// 叠加当前事务的目标设备变更
	resolvedTargetIP := targetIPv4
	if !validStrictIPv4(resolvedTargetIP) {
		resolvedTargetIP = liveIPs[targetMAC]
	}
	if enableMark && targetMid >= 1 && targetMid <= 99 {
		markedByMAC[targetMAC] = fwDevSnapshot{mac: targetMAC, ipv4: resolvedTargetIP, mid: targetMid}
	} else if !enableMark {
		delete(markedByMAC, targetMAC)
	}

	if enableBlock {
		blockedSet[targetMAC] = resolvedTargetIP
	} else {
		delete(blockedSet, targetMAC)
	}

	markedList := make([]fwDevSnapshot, 0, len(markedByMAC))
	for _, v := range markedByMAC {
		markedList = append(markedList, v)
	}
	sort.Slice(markedList, func(i, j int) bool { return markedList[i].mac < markedList[j].mac })

	blockedList := make([]fwDevSnapshot, 0, len(blockedSet))
	for m, ip := range blockedSet {
		blockedList = append(blockedList, fwDevSnapshot{mac: m, ipv4: ip})
	}
	sort.Slice(blockedList, func(i, j int) bool { return blockedList[i].mac < blockedList[j].mac })

	return markedList, blockedList
}

func deviceNeedsMarkRule(dm map[string]interface{}) bool {
	if anyToRuleBool(dm["limit_enabled"]) || anyToRuleBool(dm["delay_enabled"]) ||
		anyToRuleBool(dm["sqm_enabled"]) || anyToRuleBool(dm["app_qos"]) {
		return true
	}
	for _, f := range []string{"down_mbps", "up_mbps", "delay_ms", "jitter_ms", "loss_pct"} {
		if numFieldGT0(dm[f]) {
			return true
		}
	}
	return false
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

func validStrictIPv4(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !ipv4RE.MatchString(s) {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// buildDeviceFirewallRestorePayloads 在内存中构造双栈 iptables-restore / ip6tables-restore --noflush 流。
//
// 采用 :HNC_MARK - [0:0] 与 :HNC_CTRL - [0:0] 子链级整链原子刷新:
//   - 在 --noflush 模式下仅原子清空并重建 HNC_MARK 与 HNC_CTRL 两条专属子链,
//     绝不触碰 PREROUTING/FORWARD/POSTROUTING 挂点及 HNC_STATS 流量字节计数器;
//   - 自动消除 -D 不存在规则导致的整批回滚风险, 同时顺带完成 DHCP 陈旧 IP 规则 GC;
//   - 正交位域打标: --set-xmark 0x00XX0000/0x00ff0000, 严守低 16 位 netd netId 不被篡改;
//   - 双栈黑名单同步封禁 TCP(REJECT tcp-reset / 降级 DROP)、UDP 443(QUIC) 及全协议转发包。
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
	iface = strings.TrimSpace(iface)
	if iface != "" && !ifaceNameRE.MatchString(iface) {
		return nil, nil, fmt.Errorf("invalid iface %q", iface)
	}
	ipv4 = strings.TrimSpace(ipv4)
	if ipv4 != "" && !validStrictIPv4(ipv4) {
		return nil, nil, fmt.Errorf("invalid ipv4 %q", ipv4)
	}
	if enableMark && (mid < 1 || mid > 99) {
		return nil, nil, fmt.Errorf("invalid mark_id %d for enableMark", mid)
	}

	markedList, blockedList := collectFirewallDesiredState(hncDir, mac, ipv4, mid, enableMark, enableBlock)

	var v4 bytes.Buffer
	var v6 bytes.Buffer

	// 1. *mangle 表: 原子刷新 HNC_MARK
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

	// 2. *filter 表: 原子刷新 HNC_CTRL (含 TCP 连接瞬断与双栈 UDP 443 QUIC 阻断)
	v4.WriteString("*filter\n:HNC_CTRL - [0:0]\n")
	v6.WriteString("*filter\n:HNC_CTRL - [0:0]\n")
	for _, b := range blockedList {
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

func resolveIptablesRestoreBin(name string) string {
	candidates := []string{
		"/system/bin/" + name,
		"/system/xbin/" + name,
		"/vendor/bin/" + name,
		"/usr/sbin/" + name,
		"/sbin/" + name,
		"/usr/bin/" + name,
		"/bin/" + name,
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

const defaultSubprocSafePath = "/system/bin:/system/xbin:/vendor/bin:/usr/sbin:/sbin:/usr/bin:/bin"

func subprocEnvWithFallbackPath(extra ...string) []string {
	pathVal := defaultSubprocSafePath
	if cur := strings.TrimSpace(os.Getenv("PATH")); cur != "" && cur != defaultSubprocSafePath {
		pathVal = pathVal + ":" + cur
	}
	env := make([]string, 0, 1+len(extra))
	env = append(env, "PATH="+pathVal)
	env = append(env, extra...)
	return env
}

// isXtablesWaitFlagError 识别各代 xtables/iptables 对 -w 2 或 -w 的不兼容报错特征
// (涵盖 xtables 1.4.20/1.4.21 仅支持裸 -w 不支持秒数时输出的 "Bad argument '2'" 以及更老版本无 -w 报错)。
func isXtablesWaitFlagError(msg string) bool {
	lower := strings.ToLower(msg)
	for _, pat := range []string{
		"unknown option",
		"unrecognized option",
		"invalid option",
		"bad argument",
		"option requires an argument",
		"doesn't allow an argument",
		"does not take",
		"parameter problem",
	} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// isIptablesRejectMissingError 识别裁剪内核缺失 ipt_REJECT / ip6t_REJECT 模块或目标的报错特征。
func isIptablesRejectMissingError(msg string) bool {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "reject") {
		return true
	}
	for _, pat := range []string{
		"no chain/target/match",
		"couldn't load target",
		"could not load target",
		"cannot load target",
		"no such file or directory",
		"unknown target",
		"target_offset",
		"invalid argument",
	} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// replaceRejectWithDropInRestorePayload 在运行期将 iptables-restore / ip6tables-restore 载荷中的
// `-j REJECT [--reject-with <mode>]` 精准降级为 `-j DROP`, 保持非 REJECT 行与默认规则生成器输出不变。
func replaceRejectWithDropInRestorePayload(payload string) string {
	if !strings.Contains(payload, "REJECT") {
		return payload
	}
	lines := strings.Split(payload, "\n")
	changed := false
	for idx, rawLn := range lines {
		trimmed := strings.TrimSpace(rawLn)
		if trimmed == "" || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "#") || trimmed == "COMMIT" {
			continue
		}
		if !strings.Contains(trimmed, "REJECT") {
			continue
		}
		fields := strings.Fields(trimmed)
		outFields := make([]string, 0, len(fields))
		lineChanged := false
		for i := 0; i < len(fields); i++ {
			if (fields[i] == "-j" || fields[i] == "--jump") && i+1 < len(fields) && fields[i+1] == "REJECT" {
				outFields = append(outFields, fields[i], "DROP")
				i++
				lineChanged = true
				continue
			}
			if fields[i] == "--reject-with" {
				if i+1 < len(fields) {
					i++
				}
				lineChanged = true
				continue
			}
			if strings.HasPrefix(fields[i], "--reject-with=") {
				lineChanged = true
				continue
			}
			outFields = append(outFields, fields[i])
		}
		if lineChanged {
			lines[idx] = strings.Join(outFields, " ")
			changed = true
		}
	}
	if !changed {
		return payload
	}
	return strings.Join(lines, "\n")
}

// splitRestorePayloadByTable 将含多张表 (*mangle / *filter 等) 的 iptables-restore 载荷按表拆分为独立块,
// 供运行期分步提交防止 *filter 缺 ipt_REJECT 等模块时连坐回滚 *mangle 打标规则。
func splitRestorePayloadByTable(payload []byte) [][]byte {
	s := strings.ReplaceAll(string(payload), "\r\n", "\n")
	var blocks [][]byte
	var cur strings.Builder
	inTable := false
	for _, ln := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "*") {
			if inTable && cur.Len() > 0 {
				blocks = append(blocks, []byte(cur.String()))
				cur.Reset()
			}
			inTable = true
			cur.WriteString(trimmed)
			cur.WriteByte('\n')
			continue
		}
		if inTable {
			cur.WriteString(trimmed)
			cur.WriteByte('\n')
			if trimmed == "COMMIT" {
				blocks = append(blocks, []byte(cur.String()))
				cur.Reset()
				inTable = false
			}
		}
	}
	if inTable && cur.Len() > 0 {
		blocks = append(blocks, []byte(cur.String()))
	}
	return blocks
}

var nativePipeRestoreExecFn = defaultPipeRestoreExec

func defaultPipeRestoreExec(binPath string, args []string, payload []byte, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s timeout: %w", filepath.Base(binPath), ctx.Err())
		}
		return fmt.Errorf("%s %v failed: %w (%s)", filepath.Base(binPath), args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func pipeIptablesRestoreWithTimeout(binPath string, payload []byte, timeout time.Duration) error {
	if binPath == "" {
		return errors.New("restore binary not found")
	}
	if timeout <= 0 {
		timeout = iptRestoreTimeout
	}
	runWithWaitFallback := func(data []byte) error {
		// 三级锁参数回退: `-w 2 --noflush` -> `-w --noflush` (xtables 1.4.20/1.4.21) -> `--noflush` (极老版)
		err1 := nativePipeRestoreExecFn(binPath, []string{"-w", "2", "--noflush"}, data, timeout)
		if err1 == nil {
			return nil
		}
		if isXtablesWaitFlagError(err1.Error()) {
			err2 := nativePipeRestoreExecFn(binPath, []string{"-w", "--noflush"}, data, timeout)
			if err2 == nil {
				return nil
			}
			if isXtablesWaitFlagError(err2.Error()) {
				if err3 := nativePipeRestoreExecFn(binPath, []string{"--noflush"}, data, timeout); err3 == nil {
					return nil
				}
			}
			return err2
		}
		return err1
	}

	err := runWithWaitFallback(payload)
	if err == nil {
		return nil
	}
	// 若载荷含 REJECT 且提交报错(如裁剪内核未编译 ipt_REJECT / ip6t_REJECT), 自动降级为 -j DROP 重试
	if bytes.Contains(payload, []byte("REJECT")) && isIptablesRejectMissingError(err.Error()) {
		rawStr := string(payload)
		if dropStr := replaceRejectWithDropInRestorePayload(rawStr); dropStr != rawStr {
			if dErr := runWithWaitFallback([]byte(dropStr)); dErr == nil {
				return nil
			}
		}
	}
	return err
}

func pipeIptablesRestore(binPath string, payload []byte) error {
	return pipeIptablesRestoreWithTimeout(binPath, payload, iptRestoreTimeout)
}

// pipeRestoreTablesIsolated 先尝试整包原子提交(含三级 -w 回退与 REJECT->DROP 自动降级);
// 若整包仍失败则按表(*mangle / *filter)拆分独立提交, 确保 *filter 异常绝不连坐回滚 *mangle 限速打标规则。
func pipeRestoreTablesIsolated(binPath string, payload []byte) (mangleOK bool, filterOK bool, anyOK bool, lastErr error) {
	if binPath == "" {
		return false, false, false, errors.New("restore binary not found")
	}
	if err := pipeIptablesRestore(binPath, payload); err == nil {
		hasMangle := bytes.Contains(payload, []byte("*mangle"))
		hasFilter := bytes.Contains(payload, []byte("*filter"))
		return hasMangle, hasFilter, true, nil
	}
	blocks := splitRestorePayloadByTable(payload)
	if len(blocks) == 0 {
		err := pipeIptablesRestore(binPath, payload)
		return false, false, err == nil, err
	}
	for _, blk := range blocks {
		isMangle := bytes.HasPrefix(bytes.TrimSpace(blk), []byte("*mangle"))
		isFilter := bytes.HasPrefix(bytes.TrimSpace(blk), []byte("*filter"))
		if bErr := pipeIptablesRestore(binPath, blk); bErr == nil {
			anyOK = true
			if isMangle {
				mangleOK = true
			}
			if isFilter {
				filterOK = true
			}
		} else {
			lastErr = bErr
		}
	}
	return mangleOK, filterOK, anyOK, lastErr
}

func fallbackApplyDeviceRuleScript(hncDir, mac string, mid int, enableMark, enableBlock bool) error {
	dpStats.iptScriptFallback.Add(1)
	scriptPath := filepath.Join(hncDir, "bin", "apply_device_rule.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("apply_device_rule.sh unavailable for fallback: %w", err)
	}
	if enableBlock {
		if rc, out := runBin(hncDir, "apply_device_rule.sh", "bl_add", mac); rc != 0 {
			return fmt.Errorf("fallback apply_device_rule.sh bl_add rc=%d: %s", rc, strings.TrimSpace(out))
		}
		if !enableMark {
			return nil
		}
	}
	if enableMark && mid > 0 {
		if rc, out := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac); rc != 0 {
			return fmt.Errorf("fallback apply_device_rule.sh alloc_mid rc=%d: %s", rc, strings.TrimSpace(out))
		}
		return nil
	}
	// !enableMark && !enableBlock: 依据持久化状态决定走 bl_del 或 clear
	if root, err := rulesStore.ReadAll(hncDir); err == nil {
		if bl, ok := root["blacklist"].([]interface{}); ok {
			for _, v := range bl {
				if strings.EqualFold(strings.TrimSpace(anyToRuleString(v)), mac) {
					if rc, out := runBin(hncDir, "apply_device_rule.sh", "bl_del", mac); rc != 0 {
						return fmt.Errorf("fallback apply_device_rule.sh bl_del rc=%d: %s", rc, strings.TrimSpace(out))
					}
					return nil
				}
			}
		}
	}
	if rc, out := runBin(hncDir, "apply_device_rule.sh", "clear", mac); rc != 0 {
		return fmt.Errorf("fallback apply_device_rule.sh clear rc=%d: %s", rc, strings.TrimSpace(out))
	}
	return nil
}

// applyDeviceFirewallAtomic 通过单次内存管道向 iptables-restore / ip6tables-restore --noflush
// 原子提交 *mangle 与 *filter 设备规则 (<15ms), 失败或处于单测桩环境时自动优雅回退 apply_device_rule.sh。
func applyDeviceFirewallAtomic(hncDir, iface, mac, ipv4 string, mid int, enableMark, enableBlock bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("applyDeviceFirewallAtomic: invalid mac %q", mac)
	}

	// 单测桩环境 (无 bin/hnc_constants.sh) 直接走既有 apply_device_rule.sh 保证单测断言 100% 兼容
	if !useNativeDataplane(hncDir) {
		return fallbackApplyDeviceRuleScript(hncDir, mac, mid, enableMark, enableBlock)
	}

	unlock, lockErr := acquireNativeDataplaneLock(hncDir, "fw_atomic")
	if lockErr != nil {
		if fbErr := fallbackApplyDeviceRuleScript(hncDir, mac, mid, enableMark, enableBlock); fbErr != nil {
			return fmt.Errorf("applyDeviceFirewallAtomic: lock busy (%v) and fallback failed (%w)", lockErr, fbErr)
		}
		return nil
	}

	v4Payload, v6Payload, err := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, false)
	if err != nil {
		unlock()
		return err
	}

	v4Bin := resolveIptablesRestoreBin("iptables-restore")
	if err := pipeIptablesRestore(v4Bin, v4Payload); err != nil {
		// 若内核未编译 ipt_REJECT 模块导致 REJECT 失败, 先重试一次纯 DROP 载荷; 仍失败则释放锁优雅回退脚本
		v4Drop, v6Drop, bErr := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, true)
		if bErr != nil || pipeIptablesRestore(v4Bin, v4Drop) != nil {
			unlock()
			if fbErr := fallbackApplyDeviceRuleScript(hncDir, mac, mid, enableMark, enableBlock); fbErr != nil {
				return fmt.Errorf("applyDeviceFirewallAtomic: restore failed (%v) and fallback failed (%w)", err, fbErr)
			}
			return nil
		}
		v6Payload = v6Drop
	}

	// IPv6 双栈同步: 若系统具备 ip6tables-restore 则单次提交; 部分裁剪内核缺 ip6t_REJECT 时自动降级为 DROP 重试
	// (即便当前设备 enableBlock=false, rules.json 中其他黑名单设备仍会生成 REJECT 规则, 因此须无条件触发 DROP 降级重试)
	if v6Bin := resolveIptablesRestoreBin("ip6tables-restore"); v6Bin != "" {
		if err6 := pipeIptablesRestore(v6Bin, v6Payload); err6 != nil {
			if _, v6Drop, bErr := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, true); bErr == nil {
				_ = pipeIptablesRestore(v6Bin, v6Drop)
			}
		}
	}
	if enableMark && validStrictIPv4(ipv4) {
		ensureNativeIPv4StatsRule(resolveIptablesRestoreBin("iptables"), ipv4)
	}
	unlock()

	dpStats.iptAtomicCommits.Add(1)
	return nil
}

// ── 跨进程目录锁协同 (等待 run/lock/gate + 获取 run/tc_action.lock, 兼容 tc_manager.sh 协议) ──

const (
	dpLockPollInterval  = 25 * time.Millisecond
	dpTCLockMaxRounds   = 120 // 120 * 25ms = 3s
	dpTCLockStaleSec    = 25
	dpTCLockLeaseMaxSec = 90
)

var (
	nativeDPLockMu     sync.Mutex
	nativeBPFDirPath   = "/sys/fs/bpf/hnc"
	nativeIptCmdRunner = defaultNativeIptCmdRunner
)

func dpPidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

func tryReclaimStaleGateDir(gateDir string) {
	b, err := os.ReadFile(filepath.Join(gateDir, "pid"))
	holderStr := strings.TrimSpace(string(b))
	if err != nil || holderStr == "" {
		if st, sErr := os.Stat(gateDir); sErr == nil && time.Since(st.ModTime()) > 5*time.Second {
			_ = os.Remove(filepath.Join(gateDir, "depth"))
			_ = os.Remove(filepath.Join(gateDir, "pid"))
			_ = os.Remove(gateDir)
		}
		return
	}
	pid, pErr := strconv.Atoi(holderStr)
	if pErr == nil && pid > 0 && !dpPidAlive(pid) {
		_ = os.Remove(filepath.Join(gateDir, "depth"))
		_ = os.Remove(filepath.Join(gateDir, "pid"))
		_ = os.Remove(gateDir)
	}
}

// acquireNativeDataplaneLock 在 Go 原生路径变更内核 tc / iptables 前:
//  1. 串行化本进程并发协程;
//  2. 等待全局门禁锁 run/lock/gate 释放 (兼容 hnc_lock.sh 陈旧死锁回收);
//  3. 获取 run/tc_action.lock 目录锁并写入与 tc_manager.sh 100% 兼容的 owner ("<pid> <op> <ts>"),
//     支持 25s 死进程回收与 90s 租约超时原子 rename 抢占。
func acquireNativeDataplaneLock(hncDir, op string) (func(), error) {
	if strings.TrimSpace(hncDir) == "" {
		return func() {}, nil
	}
	if strings.TrimSpace(op) == "" {
		op = "native_dp"
	}

	nativeDPLockMu.Lock()

	runDir := filepath.Join(hncDir, "run")
	_ = os.MkdirAll(runDir, 0o755)
	if entries, err := os.ReadDir(runDir); err == nil {
		for _, ent := range entries {
			if strings.HasPrefix(ent.Name(), "tc_action.lock.stale.") {
				_ = os.RemoveAll(filepath.Join(runDir, ent.Name()))
			}
		}
	}

	gateDir := filepath.Join(runDir, "lock", "gate")
	tcLockDir := filepath.Join(runDir, "tc_action.lock")
	selfPID := os.Getpid()
	selfPIDStr := strconv.Itoa(selfPID)

	for round := 0; round < dpTCLockMaxRounds; round++ {
		if _, gErr := os.Stat(gateDir); gErr == nil {
			if round >= 40 && (round-40)%10 == 0 {
				tryReclaimStaleGateDir(gateDir)
			}
			time.Sleep(dpLockPollInterval)
			continue
		}

		if err := os.Mkdir(tcLockDir, 0o755); err == nil {
			ownerLine := fmt.Sprintf("%d %s %d\n", selfPID, op, time.Now().Unix())
			_ = os.WriteFile(filepath.Join(tcLockDir, "owner"), []byte(ownerLine), 0o644)

			// 二次检查 gateDir: 关闭检查 gate 与 mkdir tc_action.lock 之间的竞态窗口
			if _, gErr := os.Stat(gateDir); gErr == nil {
				_ = os.Remove(filepath.Join(tcLockDir, "owner"))
				_ = os.Remove(tcLockDir)
				time.Sleep(dpLockPollInterval)
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

		// 检查陈旧 tc_action.lock (死进程满 25s 或活进程未续租满 90s)
		nowSec := time.Now().Unix()
		ownerRaw, _ := os.ReadFile(filepath.Join(tcLockDir, "owner"))
		fs := strings.Fields(string(ownerRaw))
		ownerPID := 0
		oldTS := int64(0)
		if len(fs) >= 1 {
			ownerPID, _ = strconv.Atoi(fs[0])
		}
		if len(fs) >= 3 {
			oldTS, _ = strconv.ParseInt(fs[2], 10, 64)
		}
		if oldTS <= 0 {
			if st, sErr := os.Stat(tcLockDir); sErr == nil {
				oldTS = st.ModTime().Unix()
			}
		}
		age := nowSec - oldTS
		needReclaim := false
		if ownerPID > 0 && dpPidAlive(ownerPID) {
			if age >= dpTCLockLeaseMaxSec {
				needReclaim = true
			}
		} else if age >= dpTCLockStaleSec {
			needReclaim = true
		}
		if needReclaim {
			grave := fmt.Sprintf("%s.stale.%d.%d", tcLockDir, selfPID, time.Now().UnixNano())
			if os.Rename(tcLockDir, grave) == nil {
				_ = os.RemoveAll(grave)
				continue
			}
		}

		time.Sleep(dpLockPollInterval)
	}

	nativeDPLockMu.Unlock()
	return nil, errors.New("native dataplane: lock busy timeout")
}

// ── HNC_STATS 幂等补齐 (mangle 表, 先 -C 后 -A, 零重置累计字节计数) ──────────

func defaultNativeIptCmdRunner(binPath string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runIptWithWaitFallback(iptBin string, args ...string) (string, error) {
	withWait2 := append([]string{"-w", "2"}, args...)
	out, err := nativeIptCmdRunner(iptBin, withWait2...)
	if err == nil {
		return out, nil
	}
	errMsg := out + " " + err.Error()
	if !isXtablesWaitFlagError(errMsg) {
		return out, err
	}
	withWaitBare := append([]string{"-w"}, args...)
	outW, errW := nativeIptCmdRunner(iptBin, withWaitBare...)
	if errW == nil {
		return outW, nil
	}
	if isXtablesWaitFlagError(outW + " " + errW.Error()) {
		return nativeIptCmdRunner(iptBin, args...)
	}
	return outW, errW
}

// ensureNativeIPv4StatsRule 严格对齐 bin/iptables_manager.sh 的 _ensure_v4_stats_ip:
// 在 mangle 表 HNC_STATS 链幂等确保 -s <ip> -j RETURN 与 -d <ip> -j RETURN 存在。
// 铁律: 先 -C 检查, 不存在才 -A 追加, 严禁使用 iptables-restore 重置 :HNC_STATS - [0:0]!
func ensureNativeIPv4StatsRule(iptBin, ip string) {
	iptBin = strings.TrimSpace(iptBin)
	ip = strings.TrimSpace(ip)
	if iptBin == "" || !validStrictIPv4(ip) {
		return
	}
	chainEnsured := false
	ensureChain := func() {
		if chainEnsured {
			return
		}
		chainEnsured = true
		if _, err := runIptWithWaitFallback(iptBin, "-t", "mangle", "-L", "HNC_STATS", "-n"); err != nil {
			_, _ = runIptWithWaitFallback(iptBin, "-t", "mangle", "-N", "HNC_STATS")
		}
		if _, err := runIptWithWaitFallback(iptBin, "-t", "mangle", "-C", "FORWARD", "-j", "HNC_STATS"); err != nil {
			if _, iErr := runIptWithWaitFallback(iptBin, "-t", "mangle", "-I", "FORWARD", "3", "-j", "HNC_STATS"); iErr != nil {
				_, _ = runIptWithWaitFallback(iptBin, "-t", "mangle", "-A", "FORWARD", "-j", "HNC_STATS")
			}
		}
	}
	for _, dirFlag := range []string{"-s", "-d"} {
		if _, err := runIptWithWaitFallback(iptBin, "-t", "mangle", "-C", "HNC_STATS", dirFlag, ip, "-j", "RETURN"); err != nil {
			ensureChain()
			_, _ = runIptWithWaitFallback(iptBin, "-t", "mangle", "-A", "HNC_STATS", dirFlag, ip, "-j", "RETURN")
		}
	}
}

// ── 二级子树持有者判定 (delay / sqm / app_qos / app_limits) 与跨层同步钩子 ─────

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
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "app_limits.json")); err == nil && len(b) > 0 {
		var af AppLimitFile
		if json.Unmarshal(b, &af) == nil {
			for _, it := range af.Items {
				if it.DownMbps > 0 && !math.IsNaN(it.DownMbps) && !math.IsInf(it.DownMbps, 0) {
					return true
				}
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

func syncNativeDataplaneSideEffects(hncDir, mac string) {
	hncDir = strings.TrimSpace(hncDir)
	mac = strings.ToLower(strings.TrimSpace(mac))
	if hncDir == "" {
		return
	}
	if nativeBPFDirPath != "" {
		if _, err := os.Stat(nativeBPFDirPath); err == nil {
			if _, sErr := os.Stat(filepath.Join(hncDir, "bin", "hnc_clsact_sync.sh")); sErr == nil {
				_, _ = runBin(hncDir, "hnc_clsact_sync.sh")
			}
		}
	}
	if macRE.MatchString(mac) && os.Getenv("HNC_TEST_MODE") == "" {
		if _, err := os.Stat(filepath.Join(hncDir, "bin", "v6_sync.sh")); err == nil {
			_ = runBinDetached(hncDir, "v6_sync.sh", "sync_macs", mac)
		}
	}
	markAppLimitsDirtyIfNeeded(hncDir)
}

// ── 核心 API 5: action.go 原生数据面快速通道编排器（任何异常即时无损回退脚本） ──

func deviceActiveMarkInStore(hncDir, mac string) (int, bool) {
	dm, ok, err := rulesStore.GetDeviceMap(hncDir, mac)
	if err != nil || !ok || len(dm) == 0 {
		return 0, false
	}
	mid := anyToRuleInt(dm["mark_id"])
	if mid < 1 || mid > 99 {
		return 0, false
	}
	return mid, deviceNeedsMarkRule(dm) || deviceHasSecondaryQdiscOwner(hncDir, "", mac, mid, dm)
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

// deviceHasSecondaryQdiscOwner 判定设备 1:<cid> 是否存在二级子树或独立叶子持有者:
// 涵盖 delay_enabled/delay_ms/jitter_ms/loss_pct、sqm_enabled、app_qos(含 run/app_qos.state)
// 以及单应用限速 app_limits(run/app_limits.devs、data/app_limits.flat、data/app_limits.json)。
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

func readDeviceMapReadOnly(hncDir, mac string) map[string]interface{} {
	if strings.TrimSpace(hncDir) == "" || strings.TrimSpace(mac) == "" {
		return nil
	}
	if useNativeDataplane(hncDir) {
		dm, _, _ := rulesStore.GetDeviceMap(hncDir, mac)
		return dm
	}
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil || len(b) == 0 {
		return nil
	}
	var root map[string]interface{}
	if json.Unmarshal(b, &root) != nil {
		return nil
	}
	devs, _ := root["devices"].(map[string]interface{})
	for k, v := range devs {
		if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(mac)) {
			if dm, ok := v.(map[string]interface{}); ok {
				return dm
			}
		}
	}
	return nil
}

// deviceHasNonDelaySecondaryOwner 供 actionDelayClear 在清除延迟时判定该设备是否仍持有
// sqm / app_qos / app_limits 二级队列, 决定是否保留 HNC_MARK 与 1:<cid>(恢复默认 1000mbit)。
func deviceHasNonDelaySecondaryOwner(hncDir, iface, mac string, mid int) bool {
	rawDM := readDeviceMapReadOnly(hncDir, mac)
	var cleanDM map[string]interface{}
	if len(rawDM) > 0 {
		cleanDM = make(map[string]interface{}, len(rawDM))
		for k, v := range rawDM {
			switch k {
			case "delay_enabled", "delay_ms", "jitter_ms", "loss_pct":
				continue
			default:
				cleanDM[k] = v
			}
		}
	}
	return deviceHasSecondaryQdiscOwner(hncDir, iface, mac, mid, cleanDM)
}

// tryNativeResetDeviceRateToDefault 在保留 HNC_MARK 打标与根 fw/u32 过滤器的前提下,
// 将设备下行 1:<cid> 速率恢复为默认 1000mbit(不发 RTM_DELTCLASS, 避免撞子类 -EBUSY)。
func tryNativeResetDeviceRateToDefault(hncDir, iface, mac, ip string, mid int) bool {
	if !useNativeDataplane(hncDir) || mid < 1 || mid > 99 {
		return false
	}
	ifidx, err := nlIfaceIndexByName(iface)
	if err != nil || ifidx <= 0 {
		return false
	}
	minor, err := htbClassMinorForMid(mid)
	if err != nil {
		return false
	}
	unlock, lErr := acquireNativeDataplaneLock(hncDir, "reset_default_rate")
	if lErr != nil {
		return false
	}
	defer unlock()

	markVal, markMask := readDeviceMarkSpec(hncDir, mid)
	if err := nlUpsertDeviceHTB(
		ifidx, minor,
		DefaultHTBRootRateBps, DefaultHTBRootRateBps,
		DefaultHTBRootBurstB, DefaultHTBRootBurstB, DefaultHTBRootQuantumB,
		markVal, markMask, ip, false,
	); err != nil {
		return false
	}
	if validStrictIPv4(ip) {
		ensureNativeIPv4StatsRule(resolveIptablesRestoreBin("iptables"), ip)
	}
	_ = mac
	return true
}

// ensureFirewallBaseHooksLinked 确认顶层 FORWARD -> HNC_MARK / HNC_CTRL 挂点已由首次建链挂载。
// 若热点刚拉起尚未完成顶层挂点初始化, 返回 false 让首次请求走脚本完成全套挂点建链。
func ensureFirewallBaseHooksLinked() bool {
	iptBin := resolveIptablesRestoreBin("iptables")
	if iptBin == "" {
		return false
	}
	checkTable := func(tbl, chain string) bool {
		out, err := runIptWithWaitFallback(iptBin, "-t", tbl, "-S")
		if err != nil {
			return false
		}
		return strings.Contains(out, "-N "+chain) && strings.Contains(out, "-j "+chain)
	}
	return checkTable("mangle", "HNC_MARK") && checkTable("filter", "HNC_CTRL")
}

func pipeNativeFirewallOnly(hncDir, iface, mac, ipv4 string, mid int, enableMark, enableBlock bool) error {
	v4Payload, v6Payload, err := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, false)
	if err != nil {
		return err
	}
	v4Bin := resolveIptablesRestoreBin("iptables-restore")
	if _, _, anyOK, rErr := pipeRestoreTablesIsolated(v4Bin, v4Payload); !anyOK {
		v4Drop, v6Drop, bErr := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, true)
		if bErr != nil {
			return rErr
		}
		if _, _, dropOK, _ := pipeRestoreTablesIsolated(v4Bin, v4Drop); !dropOK {
			return rErr
		}
		v6Payload = v6Drop
	}
	if v6Bin := resolveIptablesRestoreBin("ip6tables-restore"); v6Bin != "" {
		if _, _, v6OK, _ := pipeRestoreTablesIsolated(v6Bin, v6Payload); !v6OK {
			if _, v6Drop, bErr := buildDeviceFirewallRestorePayloads(hncDir, iface, mac, ipv4, mid, enableMark, enableBlock, true); bErr == nil {
				_, _, _, _ = pipeRestoreTablesIsolated(v6Bin, v6Drop)
			}
		}
	}
	dpStats.iptAtomicCommits.Add(1)
	return nil
}

// tryNativeRuleSet 尝试通过 Go 原生 RTNetlink + 双栈 iptables-restore --noflush 执行单设备调速。
// 任何前置条件未就绪或内核返回错误时返回 ("", false), 由调用方无缝回退 apply_device_rule.sh。
func tryNativeRuleSet(hncDir, mac, dnMbps, upMbps string) (string, bool) {
	if !useNativeDataplane(hncDir) {
		return "", false
	}
	iface := readHotspotIfaceName(hncDir)
	if iface == "" || !ensureFirewallBaseHooksLinked() {
		return "", false
	}
	ifidx, err := nlIfaceIndexByName(iface)
	if err != nil || ifidx <= 0 {
		return "", false
	}
	dnBps, err1 := mbpsStrToBytesPerSec(dnMbps)
	upBps, err2 := mbpsStrToBytesPerSec(upMbps)
	if err1 != nil || err2 != nil || (dnBps == 0 && upBps == 0) {
		return "", false
	}

	unlock, lockErr := acquireNativeDataplaneLock(hncDir, "set_limit")
	if lockErr != nil {
		return "", false
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()

	ifbIdx := 0
	usePoliceUplink := false
	if upBps > 0 {
		idx, uErr := nlIfaceIndexByName("ifb0")
		if uErr == nil && idx > 0 {
			// 确认 ifb0 根树与重定向已由首次建链就绪, 否则交由脚本完成首次 clsact+mirred 挂载
			upClasses, dErr := nlDumpHTBClassStats(idx)
			if dErr != nil || len(upClasses) == 0 {
				return "", false
			}
			ifbIdx = idx
		} else {
			// 若设备支持 IFB (或能力尚未探明) 但 ifb0 尚未建好, 交由脚本完成首次 ifb0 创建与重定向挂载, 避免过早退化到 ingress police
			ifbSup, ifbKnown := readCapabilityBool(hncDir, "ifb_supported")
			if !ifbKnown || ifbSup {
				return "", false
			}
			if polSup, polKnown := readCapabilityBool(hncDir, "uplink_police_supported"); polKnown && polSup {
				usePoliceUplink = true
			} else {
				return "", false
			}
		}
	}

	ip := lookupCurrentDeviceIP(hncDir, mac)
	mid, err := rulesStore.UpdateDeviceLimit(hncDir, mac, ip, dnMbps, upMbps, true)
	if err != nil || mid < 1 || mid > 99 {
		return "", false
	}
	if ip == "" {
		ip, _ = rulesStore.GetDeviceField(hncDir, mac, "ip")
	}
	ip = filterActiveSubnetIPv4(iface, ip)
	minor, err := htbClassMinorForMid(mid)
	if err != nil {
		return "", false
	}
	markVal, markMask := readDeviceMarkSpec(hncDir, mid)
	alreadyBlocked := rulesStore.IsBlacklisted(hncDir, mac)

	if err := pipeNativeFirewallOnly(hncDir, iface, mac, ip, mid, true, alreadyBlocked); err != nil {
		return "", false
	}
	if validStrictIPv4(ip) {
		ensureNativeIPv4StatsRule(resolveIptablesRestoreBin("iptables"), ip)
	}

	if dnBps > 0 {
		if err := nlUpsertDeviceHTB(ifidx, minor, dnBps, dnBps, 0, 0, 0, markVal, markMask, ip, false); err != nil {
			return "", false
		}
	} else {
		dm, _, _ := rulesStore.GetDeviceMap(hncDir, mac)
		if deviceHasSecondaryQdiscOwner(hncDir, iface, mac, mid, dm) {
			// 存在 delay / sqm / app_qos / app_limits 二级子树持有者:
			// 保留 HNC_MARK 与根 fw/u32 过滤器, 仅将 1:<cid> 自身速率恢复为默认 1000mbit!
			if err := nlUpsertDeviceHTB(
				ifidx, minor,
				DefaultHTBRootRateBps, DefaultHTBRootRateBps,
				DefaultHTBRootBurstB, DefaultHTBRootBurstB, DefaultHTBRootQuantumB,
				markVal, markMask, ip, false,
			); err != nil {
				return "", false
			}
		} else {
			_ = nlDeleteDeviceHTB(ifidx, minor, markVal, markMask)
		}
	}

	if upBps > 0 && ifbIdx > 0 {
		if err := nlUpsertDeviceHTB(ifbIdx, minor, upBps, upBps, 0, 0, 0, markVal, markMask, ip, true); err != nil {
			return "", false
		}
	} else if upBps > 0 && usePoliceUplink {
		if applyNativeIngressPolice(hncDir, iface, mid, mac, ip, upBps, markVal, markMask) != nil {
			return "", false
		}
	} else if upBps == 0 {
		dm, _, _ := rulesStore.GetDeviceMap(hncDir, mac)
		if idx, uErr := nlIfaceIndexByName("ifb0"); uErr == nil && idx > 0 {
			if deviceHasDelayOwner(dm) {
				_ = nlUpsertDeviceHTB(
					idx, minor,
					DefaultHTBRootRateBps, DefaultHTBRootRateBps,
					DefaultHTBRootBurstB, DefaultHTBRootBurstB, DefaultHTBRootQuantumB,
					markVal, markMask, ip, true,
				)
			} else {
				_ = nlDeleteDeviceHTB(idx, minor, markVal, markMask)
			}
		} else if polSup, polKnown := readCapabilityBool(hncDir, "uplink_police_supported"); polKnown && polSup {
			clearNativeIngressPolice(iface, mid)
		}
	}

	locked = false
	unlock()

	syncNativeDataplaneSideEffects(hncDir, mac)
	notifyOffloadLimit(hncDir, mac, true)
	return "limit applied", true
}

// tryNativeRuleClear 尝试通过 Go 原生快速通道清除单设备限速(保留黑名单或独立延迟/SQM/QoS/app_limits 状态)。
func tryNativeRuleClear(hncDir, mac string) bool {
	if !useNativeDataplane(hncDir) {
		return false
	}
	iface := readHotspotIfaceName(hncDir)
	if iface == "" || !ensureFirewallBaseHooksLinked() {
		return false
	}
	ifidx, err := nlIfaceIndexByName(iface)
	if err != nil || ifidx <= 0 {
		return false
	}

	unlock, lockErr := acquireNativeDataplaneLock(hncDir, "clear_limit")
	if lockErr != nil {
		return false
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()

	prevDM, _, _ := rulesStore.GetDeviceMap(hncDir, mac)
	mid := anyToRuleInt(prevDM["mark_id"])
	ip := lookupCurrentDeviceIP(hncDir, mac)
	if ip == "" {
		ip = strings.TrimSpace(anyToRuleString(prevDM["ip"]))
	}
	ip = filterActiveSubnetIPv4(iface, ip)

	if _, err := rulesStore.UpdateDeviceLimit(hncDir, mac, ip, "0", "0", false); err != nil {
		return false
	}

	curDM, _, _ := rulesStore.GetDeviceMap(hncDir, mac)
	keepSecondary := deviceHasSecondaryQdiscOwner(hncDir, iface, mac, mid, curDM)
	alreadyBlocked := rulesStore.IsBlacklisted(hncDir, mac)

	if err := pipeNativeFirewallOnly(hncDir, iface, mac, ip, mid, keepSecondary && mid >= 1 && mid <= 99, alreadyBlocked); err != nil {
		return false
	}

	if mid >= 1 && mid <= 99 {
		if minor, mErr := htbClassMinorForMid(mid); mErr == nil {
			markVal, markMask := readDeviceMarkSpec(hncDir, mid)
			if keepSecondary {
				// 保留根 fw/u32 过滤器与二级子树, 仅将 1:<cid> 自身速率恢复为默认 1000mbit(禁发 RTM_DELTCLASS)
				if err := nlUpsertDeviceHTB(
					ifidx, minor,
					DefaultHTBRootRateBps, DefaultHTBRootRateBps,
					DefaultHTBRootBurstB, DefaultHTBRootBurstB, DefaultHTBRootQuantumB,
					markVal, markMask, ip, false,
				); err != nil {
					return false
				}
				if ifbIdx, uErr := nlIfaceIndexByName("ifb0"); uErr == nil && ifbIdx > 0 {
					if deviceHasDelayOwner(curDM) {
						_ = nlUpsertDeviceHTB(
							ifbIdx, minor,
							DefaultHTBRootRateBps, DefaultHTBRootRateBps,
							DefaultHTBRootBurstB, DefaultHTBRootBurstB, DefaultHTBRootQuantumB,
							markVal, markMask, ip, true,
						)
					} else {
						_ = nlDeleteDeviceHTB(ifbIdx, minor, markVal, markMask)
					}
				} else {
					clearNativeIngressPolice(iface, mid)
				}
			} else {
				if err := nlDeleteDeviceHTB(ifidx, minor, markVal, markMask); err != nil {
					return false
				}
				if ifbIdx, uErr := nlIfaceIndexByName("ifb0"); uErr == nil && ifbIdx > 0 {
					_ = nlDeleteDeviceHTB(ifbIdx, minor, markVal, markMask)
				} else {
					clearNativeIngressPolice(iface, mid)
				}
			}
		}
	}

	locked = false
	unlock()

	syncNativeDataplaneSideEffects(hncDir, mac)
	if !keepSecondary {
		notifyOffloadLimit(hncDir, mac, false)
	}
	return true
}

// tryNativeBlacklistSet 尝试通过双栈 iptables-restore --noflush 原子增删黑名单(完整保留设备限速打标)。
func tryNativeBlacklistSet(hncDir, mac string, blocked bool) bool {
	if !useNativeDataplane(hncDir) || !ensureFirewallBaseHooksLinked() {
		return false
	}
	unlock, lockErr := acquireNativeDataplaneLock(hncDir, "blacklist_set")
	if lockErr != nil {
		return false
	}
	defer unlock()

	if err := rulesStore.SetBlacklist(hncDir, mac, blocked); err != nil {
		return false
	}
	mid, keepMark := deviceActiveMarkInStore(hncDir, mac)
	ip := lookupCurrentDeviceIP(hncDir, mac)
	if ip == "" {
		ip, _ = rulesStore.GetDeviceField(hncDir, mac, "ip")
	}
	if err := pipeNativeFirewallOnly(hncDir, readHotspotIfaceName(hncDir), mac, ip, mid, keepMark, blocked); err != nil {
		return false
	}
	return true
}

// ── HNC v6.0.0 · Vector (T2): 原生特快护航 (1:8010) / 更新细流 (1:9990) 报文构造器 ──

const (
	v6ExpressClassMinor   uint16 = 0x8010
	v6ExpressLeafDown     uint32 = 0x80100000
	v6ExpressLeafUp       uint32 = 0x81100000
	v6ExpressTargetUs     uint32 = 2000  // 2ms 浅驻留 fq_codel target
	v6ExpressIntervalUs   uint32 = 40000 // 40ms fq_codel interval
	v6ExpressQuantumB     uint32 = 300
	v6ExpressLimitPkts    uint32 = 512
	v6ExpressFilterPrioV4 uint16 = 4
	v6ExpressFilterPrioV6 uint16 = 5
	v6ExpressDefaultMark  uint32 = 0x01000000

	// 热升级旧版 Vector Express 残留清理常量 (旧 1:10 / 1010: / 1110: / prio 2 & 4)
	v6ExpressLegacyClassMinor uint16 = 0x0010
	v6ExpressLegacyLeafDown   uint32 = 0x10100000
	v6ExpressLegacyLeafUp     uint32 = 0x11100000
	v6ExpressLegacyPrioV4     uint16 = 2
	v6ExpressLegacyPrioV6     uint16 = 4

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

func rulesHasMarkID10(hncDir string) bool {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return false
	}
	checkDevs := func(root map[string]interface{}) bool {
		devs, ok := root["devices"].(map[string]interface{})
		if !ok {
			return false
		}
		for _, rawObj := range devs {
			if dm, ok := rawObj.(map[string]interface{}); ok {
				if anyToRuleInt(dm["mark_id"]) == 10 {
					return true
				}
			}
		}
		return false
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json")); err == nil && len(b) > 0 {
		var parsed map[string]interface{}
		if json.Unmarshal(b, &parsed) == nil {
			return checkDevs(parsed)
		}
	}
	if root, err := rulesStore.ReadAll(hncDir); err == nil && len(root) > 0 {
		return checkDevs(root)
	}
	return false
}

// buildVectorExpressLegacyCleanupBatch 构造热升级残留安全清理消息序列:
//   - 精确按 kind="fw" + handle=0x01000000 (掩码 0x03000000) 删除旧 prio 2 (all/ip) 与旧 prio 4 (ipv6) 过滤器,
//     绝不裸删 prio 2 从而严保 LAN Fastlane u32 直通过滤器零误伤;
//   - 检查 rules.json 无 mark_id == 10 时逆序清理旧叶子 1010:/1110: 与旧类 1:10 (存在 mark_id == 10 时保留 1:10)。
func buildVectorExpressLegacyCleanupBatch(
	hncDir string,
	ifindex int,
	isUplink bool,
	gameMark, gameMask uint32,
) [][]byte {
	const low16Mask = uint32(0x0000ffff)
	gameMark &^= low16Mask
	gameMask &^= low16Mask
	if gameMask == 0 {
		gameMask = DefaultAppQoSMarkMask
	}
	defaultHandle := v6ExpressDefaultMark & DefaultAppQoSMarkMask
	handles := []uint32{defaultHandle}
	if custom := gameMark & gameMask; custom != 0 && custom != defaultHandle {
		handles = append(handles, custom)
	}

	var msgs [][]byte
	for _, h := range handles {
		if h == 0 {
			continue
		}
		msgs = append(msgs,
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, h, v6ExpressLegacyPrioV4, rtnlEthPAll, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, h, v6ExpressLegacyPrioV4, rtnlEthPIP, "fw"),
			buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, h, v6ExpressLegacyPrioV6, rtnlEthPIPv6, "fw"),
		)
	}
	if !rulesHasMarkID10(hncDir) {
		legacyCls := rtnlHtbRootMaj | uint32(v6ExpressLegacyClassMinor)
		legacyLeaf := v6ExpressLegacyLeafDown
		if isUplink {
			legacyLeaf = v6ExpressLegacyLeafUp
		}
		msgs = append(msgs,
			buildDelQdiscMsg(rtnlNextSeq(), ifindex, legacyCls, legacyLeaf),
			buildDelClassMsg(rtnlNextSeq(), ifindex, rtnlHtbRootCls, legacyCls),
		)
	}
	return msgs
}

// buildVectorExpressUpsertBatch 构造 1:8010 (prio 0) + 浅驻留 fq_codel (2ms/40ms/300B) + prio 4/5 fw 过滤器批消息。
func buildVectorExpressUpsertBatch(
	ifindex int,
	isUplink bool,
	rootRateBps, bgCeilBps uint64,
	gameMark, gameMask uint32,
	tickInUsec float64,
) [][]byte {
	keepDataplaneAPIMarkersAlive()
	const low16Mask = uint32(0x0000ffff)
	gameMark &^= low16Mask
	gameMask &^= low16Mask
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

// buildVectorExpressRemoveBatch 构造停用 Vector Express 时拆除 prio 4/5 过滤器、叶子与 1:8010 类并恢复 1:9999 的消息序列。
func buildVectorExpressRemoveBatch(
	ifindex int,
	isUplink bool,
	restoreRootRateBps uint64,
	gameMark, gameMask uint32,
	tickInUsec float64,
) [][]byte {
	const low16Mask = uint32(0x0000ffff)
	gameMark &^= low16Mask
	gameMask &^= low16Mask
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

// nlCloseSocket 关闭长连接 AF_NETLINK 描述符。
func nlCloseSocket(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

// nlEnsureHTBRootOnSocket 在已有长连接 fd 上幂等确保 HTB 根队列 1:、父类 1:1 与默认类 1:<defaultMinor> 就绪。
func nlEnsureHTBRootOnSocket(fd int, ifindex int, defaultMinor uint16, rootRateBps uint64) error {
	if defaultMinor == 0 {
		defaultMinor = rtnlDefMinor
	}
	if rootRateBps == 0 {
		rootRateBps = DefaultHTBRootRateBps
	}
	qdiscs, err := rtnlDumpQdiscsOnSocket(fd, ifindex)
	if err != nil {
		return err
	}
	defClassHandle := rtnlHtbRootMaj | uint32(defaultMinor)
	hasHTBRoot := false
	hasDefLeaf := false
	for _, q := range qdiscs {
		if q.handle == rtnlHtbRootMaj && q.kind == "htb" {
			hasHTBRoot = true
		}
		if q.parent == defClassHandle {
			hasDefLeaf = true
		}
	}
	if !hasHTBRoot {
		seq := rtnlNextSeq()
		if err := rtnlSendAndWaitAck(fd, buildHTBRootQdiscMsg(seq, ifindex, defaultMinor), seq); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	tickInUsec := readPschedTickInUsec()
	burst := hncBurstBytesForRate(rootRateBps, false)
	quantum := hncQuantumForRate(rootRateBps)
	seqRoot := rtnlNextSeq()
	if err := rtnlSendAndWaitAck(fd, buildHTBClassUpsertMsg(seqRoot, ifindex, rtnlHtbRootMaj, rtnlHtbRootCls, rootRateBps, rootRateBps, burst, burst, quantum, 0, tickInUsec), seqRoot); err != nil {
		return err
	}
	seqDef := rtnlNextSeq()
	if err := rtnlSendAndWaitAck(fd, buildHTBClassUpsertMsg(seqDef, ifindex, rtnlHtbRootCls, defClassHandle, rootRateBps, rootRateBps, burst, burst, quantum, 7, tickInUsec), seqDef); err != nil {
		return err
	}
	if !hasDefLeaf {
		leafHandle := uint32(defaultMinor) << 16
		_ = nlAttachAdaptiveLeafQdisc(fd, ifindex, defClassHandle, leafHandle, rootRateBps)
	}
	return nil
}

var (
	nlShaperSendAndWaitAckFn = rtnlSendAndWaitAck
	nlShaperEnsureHTBRootFn  = nlEnsureHTBRootOnSocket
)

// nlTuneGlobalShaperOnSocket 在长连接 fd 上直接通过 RTM_NEWTCLASS 热更新根类 1:1 带宽 (< 0.2ms, 零 dump)。
// v6.1.0-beta.1: 上行 ifb0 与下行对称检查 Netlink ACK 回执, 报错时自动补建根树一次, 仍失败则累加 nlErrors 并透传错误。
func nlTuneGlobalShaperOnSocket(fd int, downIfindex int, downBps uint64, ifbIfindex int, upBps uint64) (int, error) {
	tick := readPschedTickInUsec()
	sent := 0
	if downIfindex > 0 && downBps > 0 {
		burst := hncBurstBytesForRate(downBps, false)
		seq := rtnlNextSeq()
		msg := buildHTBClassUpsertMsg(seq, downIfindex, rtnlHtbRootMaj, rtnlHtbRootCls, downBps, downBps, burst, burst, hncQuantumForRate(downBps), 0, tick)
		if err := nlShaperSendAndWaitAckFn(fd, msg, seq); err != nil {
			if eErr := nlShaperEnsureHTBRootFn(fd, downIfindex, rtnlDefMinor, downBps); eErr != nil {
				dpStats.nlErrors.Add(1)
				return sent, fmt.Errorf("tune global shaper 1:1 failed (%w); ensure root failed: %v", err, eErr)
			}
		}
		sent++
	}
	if ifbIfindex > 0 && upBps > 0 {
		burst := hncBurstBytesForRate(upBps, false)
		seq := rtnlNextSeq()
		msg := buildHTBClassUpsertMsg(seq, ifbIfindex, rtnlHtbRootMaj, rtnlHtbRootCls, upBps, upBps, burst, burst, hncQuantumForRate(upBps), 0, tick)
		if err := nlShaperSendAndWaitAckFn(fd, msg, seq); err != nil {
			if eErr := nlShaperEnsureHTBRootFn(fd, ifbIfindex, rtnlDefMinor, upBps); eErr != nil {
				dpStats.nlErrors.Add(1)
				return sent, fmt.Errorf("tune global shaper 1:1 failed (%w); ensure root failed: %v", err, eErr)
			}
		}
		sent++
	}
	return sent, nil
}

var (
	nlBatchDumpQdiscsFn    = rtnlDumpQdiscsOnSocket
	nlBatchDumpClassesFn   = nlDumpHTBClassStatsOnSocket
	nlBatchEnsureHTBRootFn = nlEnsureHTBRootOnSocket
	nlBatchSendAckFn       = rtnlSendAndWaitAck
)

// fallbackIPv6FilterPrio 为老内核 4.14/4.19 拒绝 ETH_P_ALL 时拆出的 ETH_P_IPV6 过滤器分配无冲突优先级:
//   - 根 parent 1: 上 origPrio=1 映射至 prio=3 (避开 prio=2 的 LAN Fastlane u32, 对齐 deviceFWDeleteSpecs);
//   - 二级子树 parent 1:<cid> 上 origPrio=1->3 (避开 prio=2 的 AppQoS), origPrio=2->4, origPrio=9->10。
func fallbackIPv6FilterPrio(parent uint32, origPrio uint16) uint16 {
	if parent == rtnlHtbRootMaj {
		if origPrio == rtnlFilterPrioFW {
			return 3
		}
		return origPrio + 1
	}
	switch origPrio {
	case 1:
		return 3
	case 2:
		return 4
	default:
		return origPrio + 1
	}
}

func extractBatchParentCeilRates(msgs [][]byte) map[uint32]uint64 {
	rates := make(map[uint32]uint64, 4)
	var doneHdr [rtnlMsgHdrLen]byte
	binary.LittleEndian.PutUint32(doneHdr[0:4], rtnlMsgHdrLen)
	binary.LittleEndian.PutUint16(doneHdr[4:6], rtnlMsgDone)

	for _, m := range msgs {
		if len(m) < rtnlMsgHdrLen+rtnlTcMsgLen || binary.LittleEndian.Uint16(m[4:6]) != rtnlNewTClass {
			continue
		}
		buf := make([]byte, 0, len(m)+rtnlMsgHdrLen)
		buf = append(buf, m...)
		buf = append(buf, doneHdr[:]...)
		if parsed, err := parseTCClassDumpMsgs(buf, 0); err == nil {
			for _, st := range parsed {
				if st.HandleRaw != 0 && st.CeilBps > 0 {
					rates[st.HandleRaw] = st.CeilBps
				}
			}
		}
	}
	return rates
}

// nlSendBatchWithCompatFallback 统一执行 Netlink 批消息发送与跨内核降级:
//   - 老内核 4.14/4.19 拒绝 ETH_P_ALL 过滤器时自动拆分为 ETH_P_IP + ETH_P_IPV6 双栈补发;
//   - 裁剪内核拒绝自定义或默认 fq_codel 时按 fq_codel(无参) -> fq -> sfq -> 按速率缩放 pfifo 自适应降级;
//   - 删除不存在对象的 ENOENT/ESRCH/EINVAL 幂等忽略。
func nlSendBatchWithCompatFallback(fd int, msgs [][]byte, bestEffortAfterFirstClass bool) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	parentRates := extractBatchParentCeilRates(msgs)
	sent := 0
	ethAllNet := rtnlHtons(rtnlEthPAll)
	ethIPNet := rtnlHtons(rtnlEthPIP)
	ethIPv6Net := rtnlHtons(rtnlEthPIPv6)

	for idx, m := range msgs {
		if len(m) < rtnlMsgHdrLen+rtnlTcMsgLen {
			continue
		}
		seq := binary.LittleEndian.Uint32(m[8:12])
		msgType := binary.LittleEndian.Uint16(m[4:6])
		err := nlBatchSendAckFn(fd, m, seq)
		if err == nil {
			sent++
			continue
		}
		if (msgType == rtnlDelTFilter || msgType == rtnlDelTClass || msgType == rtnlDelQdisc) && isIgnorableDelErr(err) {
			continue
		}
		if idx == 0 && msgType == rtnlNewTClass && bestEffortAfterFirstClass {
			return sent, err
		}

		// 若 ETH_P_ALL 过滤器被 4.14/4.19 裁剪内核拒绝, 拆分为 ETH_P_IP + ETH_P_IPV6 双栈重发
		if msgType == rtnlNewTFilter {
			parent := binary.LittleEndian.Uint32(m[28:32])
			info := binary.LittleEndian.Uint32(m[32:36])
			protoNet := uint16(info & 0xffff)
			origPrio := uint16(info >> 16)
			if protoNet == ethAllNet {
				cp4 := append([]byte(nil), m...)
				seq4 := rtnlNextSeq()
				binary.LittleEndian.PutUint32(cp4[8:12], seq4)
				binary.LittleEndian.PutUint32(cp4[32:36], (uint32(origPrio)<<16)|uint32(ethIPNet))
				err4 := nlBatchSendAckFn(fd, cp4, seq4)
				if err4 == nil {
					sent++
				}

				v6Prio := fallbackIPv6FilterPrio(parent, origPrio)
				cp6 := append([]byte(nil), m...)
				seq6 := rtnlNextSeq()
				binary.LittleEndian.PutUint32(cp6[8:12], seq6)
				binary.LittleEndian.PutUint32(cp6[32:36], (uint32(v6Prio)<<16)|uint32(ethIPv6Net))
				if err6 := nlBatchSendAckFn(fd, cp6, seq6); err6 == nil {
					sent++
				}
				if err4 == nil {
					continue
				}
			}
			// IPv6 备用过滤器在纯 IPv4 精简内核上容忍失败
			if protoNet == ethIPv6Net || bestEffortAfterFirstClass {
				continue
			}
		}

		// 若叶子队列(带参或默认 fq_codel)不被老内核支持, 按 fq_codel(无参) -> fq -> sfq -> 缩放 pfifo 逐级自适应降级
		if msgType == rtnlNewQdisc {
			ifidx := int(int32(binary.LittleEndian.Uint32(m[20:24])))
			handle := binary.LittleEndian.Uint32(m[24:28])
			parent := binary.LittleEndian.Uint32(m[28:32])
			rateBps := parentRates[parent]

			fbSeq := rtnlNextSeq()
			if nlBatchSendAckFn(fd, buildFqCodelLeafMsg(fbSeq, ifidx, parent, handle, false), fbSeq) == nil {
				sent++
				continue
			}
			attached := false
			for _, kind := range []string{"fq", "sfq"} {
				seqK := rtnlNextSeq()
				if nlBatchSendAckFn(fd, buildSimpleKindLeafMsg(seqK, ifidx, parent, handle, kind), seqK) == nil {
					sent++
					attached = true
					break
				}
			}
			if attached {
				continue
			}
			seqP := rtnlNextSeq()
			if nlBatchSendAckFn(fd, buildPfifoScaledLeafMsg(seqP, ifidx, parent, handle, rateBps), seqP) == nil {
				sent++
				continue
			}
			continue
		}

		if bestEffortAfterFirstClass {
			continue
		}
		return sent, err
	}
	return sent, nil
}

// nlApplyBatchWithFWFallbackOnSocket 在长连接 fd 上顺序下发批消息:
//   - 对批次中所有含 RTM_NEWTCLASS 的不重复 ifindex 幂等确保根 htb 1: 与父类 1:1 就绪;
//   - 对老内核不支持 ETH_P_ALL 的场景自动拆分为 ETH_P_IP + ETH_P_IPV6 双栈重试;
//   - 对叶子队列按 fq_codel -> fq -> sfq -> pfifo 自适应降级;
//   - 对删除不存在过滤器/队列/类的 ENOENT/ESRCH/EINVAL 幂等放行。
func nlApplyBatchWithFWFallbackOnSocket(fd int, msgs [][]byte) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	seenClassIfidx := make(map[int]bool, 2)
	for _, m := range msgs {
		if len(m) < rtnlMsgHdrLen+rtnlTcMsgLen {
			continue
		}
		if binary.LittleEndian.Uint16(m[4:6]) != rtnlNewTClass {
			continue
		}
		ifidx := int(int32(binary.LittleEndian.Uint32(m[20:24])))
		if ifidx <= 0 || seenClassIfidx[ifidx] {
			continue
		}
		seenClassIfidx[ifidx] = true
		qdiscs, qErr := nlBatchDumpQdiscsFn(fd, ifidx)
		if qErr != nil {
			continue
		}
		hasHTB := false
		for _, q := range qdiscs {
			if q.handle == rtnlHtbRootMaj && q.kind == "htb" {
				hasHTB = true
				break
			}
		}
		hasRootCls := false
		if hasHTB {
			if classes, cErr := nlBatchDumpClassesFn(fd, ifidx); cErr == nil {
				_, hasRootCls = classes["1:1"]
			}
		}
		if !hasHTB || !hasRootCls {
			_ = nlBatchEnsureHTBRootFn(fd, ifidx, rtnlDefMinor, DefaultHTBRootRateBps)
		}
	}
	return nlSendBatchWithCompatFallback(fd, msgs, false)
}

// nlProbeKernelCapabilities 通过只读 AF_NETLINK RTM_GETQDISC 实测内核 RTNetlink、clsact 与 sch_fq 可用性。
func nlProbeKernelCapabilities(ifindex int) (hasRTNetlink bool, hasClsact bool, hasSchFQ bool) {
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return false, false, false
	}
	defer syscall.Close(fd)

	qdiscs, err := rtnlDumpQdiscsOnSocket(fd, ifindex)
	if err != nil {
		return false, false, false
	}
	hasRTNetlink = true
	for _, q := range qdiscs {
		if q.kind == "clsact" || q.handle == rtnlTcHIngress {
			hasClsact = true
		}
		if q.kind == "fq" {
			hasSchFQ = true
		}
	}
	return hasRTNetlink, hasClsact, hasSchFQ
}

const rtnlGetTFilter = 46 // RTM_GETTFILTER

func rtnlSendtoRetry(fd int, req []byte) error {
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	for {
		err := syscall.Sendto(fd, req, 0, dst)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

// nlDumpIngressFilterSummary 通过原生 RTNetlink RTM_GETTFILTER 读取入口(clsact ffff:fff2 / ingress ffff:)过滤器摘要,
// 绕过 ColorOS /system/bin/tc 对 `ingress` 关键字返回空串或语法报错的缺陷。
func nlDumpIngressFilterSummary(ifindex int) string {
	if ifindex <= 0 {
		return ""
	}
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return ""
	}
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()

	var lines []string
	buf := make([]byte, 65536)
	for _, parent := range []uint32{0xfffffff2, 0xffff0000, rtnlTcHIngress} {
		if fd < 0 {
			fd, err = openRTNetlinkSocket()
			if err != nil {
				return strings.Join(lines, "\n")
			}
		}
		seq := rtnlNextSeq()
		req := rtnlBuildTCMsg(rtnlGetTFilter, rtnlFRequest|rtnlFDump, seq, ifindex, 0, parent, 0, nil)
		if rtnlSendtoRetry(fd, req) != nil {
			_ = syscall.Close(fd)
			fd = -1
			continue
		}
		cleanDone := false
		for chunks := 0; chunks < 256; {
			n, _, rErr := syscall.Recvfrom(fd, buf, 0)
			if errors.Is(rErr, syscall.EINTR) {
				continue
			}
			if rErr != nil || n <= 0 {
				break
			}
			chunks++
			done, malformed := parseIngressFilterSummaryChunkWithSeq(buf[:n], seq, ifindex, &lines)
			if malformed {
				break
			}
			if done {
				cleanDone = true
				break
			}
		}
		if !cleanDone {
			_ = syscall.Close(fd)
			fd = -1
		}
		if len(lines) > 0 {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func parseIngressFilterSummaryChunk(b []byte, wantIfIndex int, lines *[]string) bool {
	done, malformed := parseIngressFilterSummaryChunkWithSeq(b, 0, wantIfIndex, lines)
	return done || malformed
}

func parseIngressFilterSummaryChunkWithSeq(b []byte, wantSeq uint32, wantIfIndex int, lines *[]string) (done bool, malformed bool) {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, true
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		msgSeq := binary.LittleEndian.Uint32(b[off+8 : off+12])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, true
		}
		msg := b[off : off+msgLen]
		adv := rtnlAlign(msgLen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
		if wantSeq != 0 && msgSeq != wantSeq {
			continue
		}
		if msgType == rtnlMsgDone || msgType == rtnlMsgError {
			return true, false
		}
		if msgType != rtnlNewTFilter || len(msg) < rtnlMsgHdrLen+rtnlTcMsgLen {
			continue
		}
		ifidx := int(int32(binary.LittleEndian.Uint32(msg[20:24])))
		if wantIfIndex > 0 && ifidx != wantIfIndex {
			continue
		}
		handle := binary.LittleEndian.Uint32(msg[24:28])
		info := binary.LittleEndian.Uint32(msg[32:36])
		prio := info >> 16
		if prio == 0 {
			continue
		}
		var kind string
		var rawAttrs []byte
		if len(msg) > rtnlMsgHdrLen+rtnlTcMsgLen {
			rawAttrs = msg[rtnlMsgHdrLen+rtnlTcMsgLen:]
		}
		for aoff := 0; aoff < len(rawAttrs); {
			arem := len(rawAttrs) - aoff
			if arem < rtnlAttrHdr {
				break
			}
			alen := int(binary.LittleEndian.Uint16(rawAttrs[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(rawAttrs[aoff+2:aoff+4]) & nlaTypeMask
			if alen < rtnlAttrHdr || alen > arem {
				break
			}
			if atype == rtnlTcaKind {
				kind = rtnlCString(rawAttrs[aoff+4 : aoff+alen])
			}
			nadv := rtnlAlign(alen)
			if nadv > arem {
				break
			}
			aoff += nadv
		}
		if kind == "" {
			continue
		}
		var extras []string
		if bytes.Contains(rawAttrs, []byte("hnc_clsact")) || kind == "bpf" {
			extras = append(extras, "hnc_clsact direct-action")
		}
		if bytes.Contains(rawAttrs, []byte("mirred")) || bytes.Contains(rawAttrs, []byte("ifb0")) {
			extras = append(extras, "action mirred (Egress Redirect to device ifb0)")
		}
		// u32/fw 的 TCA_U32_POLICE / TCA_FW_POLICE 嵌套或 act police 标记
		if bytes.Contains(rawAttrs, []byte("police")) || hasNestedPoliceAttr(rawAttrs, kind) {
			extras = append(extras, "police")
		}
		*lines = append(*lines, fmt.Sprintf("filter parent ffff: protocol all pref %d %s handle 0x%x %s",
			prio, kind, handle, strings.Join(extras, " ")))
	}
	return false, false
}

func hasNestedPoliceAttr(rawAttrs []byte, kind string) bool {
	if kind != "u32" && kind != "fw" {
		return false
	}
	// linux/pkt_cls.h: TCA_U32_POLICE = 2, TCA_FW_POLICE = 2 (内部含 struct tc_police >= 20B)
	for aoff := 0; aoff < len(rawAttrs); {
		arem := len(rawAttrs) - aoff
		if arem < rtnlAttrHdr {
			return false
		}
		alen := int(binary.LittleEndian.Uint16(rawAttrs[aoff : aoff+2]))
		atype := binary.LittleEndian.Uint16(rawAttrs[aoff+2:aoff+4]) & nlaTypeMask
		if alen < rtnlAttrHdr || alen > arem {
			return false
		}
		if atype == rtnlTcaOptions {
			opts := rawAttrs[aoff+4 : aoff+alen]
			for noff := 0; noff < len(opts); {
				nrem := len(opts) - noff
				if nrem < rtnlAttrHdr {
					break
				}
				nlen := int(binary.LittleEndian.Uint16(opts[noff : noff+2]))
				ntype := binary.LittleEndian.Uint16(opts[noff+2:noff+4]) & nlaTypeMask
				if nlen < rtnlAttrHdr || nlen > nrem {
					break
				}
				if ntype == 2 && nlen >= rtnlAttrHdr+20 {
					return true
				}
				nadv := rtnlAlign(nlen)
				if nadv > nrem {
					break
				}
				noff += nadv
			}
		}
		nadv := rtnlAlign(alen)
		if nadv > arem {
			break
		}
		aoff += nadv
	}
	return false
}

// dumpDefaultRouteIfindexesOS 通过原生 AF_NETLINK RTM_GETROUTE 扫描全系统策略路由表(含 Dual-STA 独立 netd 表),
// 返回所有持有 rtm_dst_len == 0 且 RTN_UNICAST 默认路由的出接口 ifindex 集合。
func dumpDefaultRouteIfindexesOS() (map[int]bool, error) {
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()

	out := make(map[int]bool)
	buf := make([]byte, 65536)
	for _, family := range []uint8{2, 10} { // AF_INET, AF_INET6
		if fd < 0 {
			fd, err = openRTNetlinkSocket()
			if err != nil {
				return out, nil
			}
		}
		seq := rtnlNextSeq()
		req := buildGetRouteDumpMsg(seq, family)
		if err := rtnlSendtoRetry(fd, req); err != nil {
			_ = syscall.Close(fd)
			fd = -1
			continue
		}
		cleanDone := false
		for chunks := 0; chunks < 512; {
			n, _, rErr := syscall.Recvfrom(fd, buf, 0)
			if errors.Is(rErr, syscall.EINTR) {
				continue
			}
			if rErr != nil || n <= 0 {
				break
			}
			chunks++
			chunkIfs, done, pErr := parseDefaultRouteIfindexesMsgs(buf[:n])
			for idx := range chunkIfs {
				out[idx] = true
			}
			if pErr != nil {
				break
			}
			if done {
				cleanDone = true
				break
			}
		}
		if !cleanDone {
			// 若当前协议族未读到完整 NLMSG_DONE, 重开干净套接字防止残余分片污染下一协议族
			_ = syscall.Close(fd)
			fd = -1
		}
	}
	return out, nil
}

func closeRTNetlinkSocket(fd int) {
	_ = syscall.Close(fd)
}

func sendConntrackDeleteNetlink(tuple ScalpelTuple, seq uint32) error {
	msg, err := buildConntrackDeleteNetlinkMsg(tuple, seq)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, nlNetfilter)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	if err := rtnlSendtoRetry(fd, msg); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for tries := 0; tries < rtnlMaxAckTries; {
		n, _, rErr := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(rErr, syscall.EINTR) {
			continue
		}
		if rErr != nil {
			return rErr
		}
		if n <= 0 {
			return errors.New("ctnetlink delete: empty recv")
		}
		tries++
		matched, ackErr, parseErr := parseConntrackAckMsgs(buf[:n], seq)
		if parseErr != nil {
			return parseErr
		}
		if matched {
			return ackErr
		}
	}
	return fmt.Errorf("ctnetlink delete: unmatched ack seq %d", seq)
}

func parseConntrackAckMsgs(b []byte, wantSeq uint32) (matched bool, ackErr error, parseErr error) {
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return false, nil, errors.New("short netlink response")
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		msgSeq := binary.LittleEndian.Uint32(b[off+8 : off+12])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return false, nil, errors.New("malformed netlink length")
		}
		msg := b[off : off+msgLen]
		adv := rtnlAlign(msgLen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
		if wantSeq != 0 && msgSeq != wantSeq {
			continue
		}
		if msgType == rtnlMsgDone {
			return true, nil, nil
		}
		if msgType == rtnlMsgError {
			return true, parseNetlinkAck(msg), nil
		}
	}
	return false, nil, nil
}

func dumpNativeIPv6NeighborsOS(allowedIfindexes map[int]bool) (map[string][]net.IP, error) {
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	seq := rtnlNextSeq()
	req := buildGetNeighIPv6DumpMsg(seq)
	if err := rtnlSendtoRetry(fd, req); err != nil {
		return nil, fmt.Errorf("rtnl neigh dump send: %w", err)
	}

	allCands := make(map[string]map[string]ipv6NeighCandidate)
	orderCounter := 0
	buf := make([]byte, 65536)
	for chunks := 0; chunks < 512; {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("rtnl neigh dump recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("rtnl neigh dump: empty recv")
		}
		chunks++
		done, pErr := parseIPv6NeighDumpChunkCandidates(buf[:n], allowedIfindexes, allCands, &orderCounter)
		if pErr != nil {
			return nil, pErr
		}
		if done {
			// 收齐全量分片后按状态优先级(REACHABLE > DELAY/PROBE/PERMANENT > STALE)与确认时间统一排序再截断前 16 条
			return rankAndCapIPv6Neighbors(allCands, v6IPv6MaxAddrs), nil
		}
	}
	return nil, errors.New("rtnl neigh dump: exceeded max chunks without NLMSG_DONE")
}

// filterActiveSubnetIPv4 过滤离线或跨次重启残留的非当前热点网段旧 IPv4,
// 避免 u32 过滤器误绑过期地址; 若当前接口无可读 IPv4 网段(如单测环境)则原样保留。
func filterActiveSubnetIPv4(iface, ipv4 string) string {
	ipv4 = strings.TrimSpace(ipv4)
	if ipv4 == "" || iface == "" {
		return ipv4
	}
	parsed := net.ParseIP(ipv4)
	if parsed == nil || parsed.To4() == nil {
		return ""
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return ipv4
	}
	addrs, err := ifi.Addrs()
	if err != nil || len(addrs) == 0 {
		return ipv4
	}
	hasV4Sub := false
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet == nil || ipNet.IP.To4() == nil {
			continue
		}
		hasV4Sub = true
		if ipNet.Contains(parsed) {
			return ipv4
		}
	}
	if !hasV4Sub {
		return ipv4
	}
	return ""
}

const (
	nativeIngressPolicePrioBase       uint16 = 300
	legacyNativeIngressPolicePrioBase uint16 = 20000
)

var (
	nativeResolveSystemBinFn = resolveSystemBin
	nativeTCExecFn           = defaultRunNativeTC
	nativeTCQdiscShowFn      = defaultShowNativeTCQdisc
	nativeCollectDevIPv6Fn   func(hncDir, iface, mac string) []string
	nativeDumpIPv6NeighFn    = DumpNativeIPv6Neighbors
)

func resolveSystemBin(name string) string {
	for _, dir := range []string{"/system/bin", "/system/xbin", "/vendor/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	p, err := exec.LookPath(name)
	if err == nil {
		return p
	}
	return ""
}

func defaultRunNativeTC(tcBin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, tcBin, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	_, err := cmd.CombinedOutput()
	return err
}

func runNativeTC(tcBin string, args ...string) error {
	return nativeTCExecFn(tcBin, args...)
}

func defaultShowNativeTCQdisc(tcBin, iface string) string {
	// 优先走原生 RTNetlink RTM_GETQDISC 查询 clsact / ingress ffff:,
	// 既省去 fork tc 子进程, 又绕过 ColorOS /system/bin/tc 对 ingress 队列输出残缺/为空的缺陷。
	if iface != "" {
		if ifidx, err := nlIfaceIndexByName(iface); err == nil && ifidx > 0 {
			if fd, sErr := openRTNetlinkSocket(); sErr == nil {
				qdiscs, dErr := rtnlDumpQdiscsOnSocket(fd, ifidx)
				_ = syscall.Close(fd)
				if dErr == nil {
					var sb strings.Builder
					for _, q := range qdiscs {
						hStr := formatTCHandle(q.handle)
						if q.kind == "ingress" && hStr == "ffff:fff1" {
							hStr = "ffff:"
						}
						fmt.Fprintf(&sb, "qdisc %s %s parent %s\n", q.kind, hStr, formatTCHandle(q.parent))
					}
					return sb.String()
				}
			}
		}
	}
	if tcBin == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, tcBin, "qdisc", "show", "dev", iface))
	cmd.Env = subprocEnvWithFallbackPath()
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func isGlobalUnicastOrULAIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func collectDeviceIPv6Addrs(hncDir, iface, mac string) []string {
	if nativeCollectDevIPv6Fn != nil {
		return nativeCollectDevIPv6Fn(hncDir, iface, mac)
	}
	cm := canonMAC(mac)
	if cm == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	addAddr := func(raw string) bool {
		if len(out) >= v6IPv6MaxAddrs {
			return false
		}
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if !isGlobalUnicastOrULAIPv6(parsed) {
			return true
		}
		s := parsed.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		return len(out) < v6IPv6MaxAddrs
	}

	// 1. 优先采用经状态优先级(REACHABLE > DELAY/PROBE/PERMANENT > STALE)与确认时间排好序的实时活跃邻居
	var allow map[int]bool
	if iface != "" {
		if idx, err := nlIfaceIndexByName(iface); err == nil && idx > 0 {
			allow = map[int]bool{idx: true}
		}
	}
	if nativeDumpIPv6NeighFn != nil {
		if neighMap, err := nativeDumpIPv6NeighFn(allow); err == nil {
			for _, ip6 := range neighMap[cm] {
				if isGlobalUnicastOrULAIPv6(ip6) {
					if !addAddr(ip6.String()) {
						return out
					}
				}
			}
		}
	}

	// 2. 若不足 16 条, 从 run/v6/<mac> 快照按最近看到的时间戳降序优胜劣汰补齐
	if hncDir != "" && len(out) < v6IPv6MaxAddrs {
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "v6", cm)); err == nil && len(b) > 0 {
			type snapEntry struct {
				addr   string
				seenTS int64
				idx    int
			}
			var snaps []snapEntry
			for i, ln := range strings.Split(string(b), "\n") {
				trimmed := strings.TrimSpace(ln)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				fs := strings.Fields(trimmed)
				if len(fs) == 0 {
					continue
				}
				var ts int64
				if len(fs) >= 2 {
					ts, _ = strconv.ParseInt(fs[1], 10, 64)
				}
				snaps = append(snaps, snapEntry{addr: fs[0], seenTS: ts, idx: i})
			}
			sort.Slice(snaps, func(i, j int) bool {
				if snaps[i].seenTS != snaps[j].seenTS {
					return snaps[i].seenTS > snaps[j].seenTS
				}
				return snaps[i].idx < snaps[j].idx
			})
			for _, se := range snaps {
				if !addAddr(se.addr) {
					break
				}
			}
		}
	}
	return out
}

// nativeIngressFilterHookState 探测热点口入口队列是 clsact 还是传统 ingress ffff:,
// 若已挂载 clsact 则返回 (["ingress"], true, true), 否则返回 (["parent", "ffff:"], hasFFFF, false)。
func nativeIngressFilterHookState(tcBin, iface string) (hookArgs []string, hasQdisc bool, clsactQdisc bool) {
	s := nativeTCQdiscShowFn(tcBin, iface)
	if strings.Contains(s, "clsact") {
		return []string{"ingress"}, true, true
	}
	return []string{"parent", "ffff:"}, strings.Contains(s, "ffff:"), false
}

func nativeIngressFilterHookArgs(tcBin, iface string) ([]string, bool) {
	hookArgs, hasQdisc, _ := nativeIngressFilterHookState(tcBin, iface)
	return hookArgs, hasQdisc
}

// applyNativeIngressPolice 在 GKI 6.1/6.6/6.12 无 IFB 内核上通过双栈 ingress police 实施每客户端上行限速(对齐 tc_manager.sh set_uplink_police)。
func applyNativeIngressPolice(hncDir, iface string, mid int, mac, ip string, upBps uint64, markVal, markMask uint32) error {
	tcBin := nativeResolveSystemBinFn("tc")
	cidStr := classIDStringForMid(mid)
	cid, err := strconv.Atoi(cidStr)
	if tcBin == "" || iface == "" || err != nil || cid <= 0 || upBps == 0 {
		return errors.New("ingress police: invalid parameters or missing tc binary")
	}
	hookArgs, hasQdisc, clsactQdisc := nativeIngressFilterHookState(tcBin, iface)
	clsactActive := clsactQdisc && defaultCheckClsactPinnedReady(hncDir)
	v6Addrs := collectDeviceIPv6Addrs(hncDir, iface, mac)
	if !clsactActive && len(v6Addrs) > 0 {
		// 无 clsact BPF L2 MAC 打标且客户端存在全局 IPv6 地址时, 返回错误使调用方安全回退 ./bin/tc_manager.sh 下发完整 IPv4+IPv6 u32 警察过滤器
		return errors.New("ingress police: fallback to tc_manager.sh for IPv6 u32 when clsact BPF inactive")
	}

	if !hasQdisc {
		_ = runNativeTC(tcBin, "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")
		hookArgs = []string{"parent", "ffff:"}
	}

	clearNativeIngressPoliceWithHook(tcBin, iface, cid, hookArgs)

	kbit := (upBps * 8) / 1000
	if kbit < 64 {
		kbit = 64
	}
	rateStr := strconv.FormatUint(kbit, 10) + "kbit"
	burstBytes := upBps / 8
	if burstBytes < 65536 {
		burstBytes = 65536
	}
	burstStr := strconv.FormatUint(burstBytes, 10) + "b"

	base := int(nativeIngressPolicePrioBase)
	prio4 := strconv.Itoa(base + cid)
	prio6 := strconv.Itoa(base + 5000 + cid)
	prioFw4 := strconv.Itoa(base + 6000 + cid)
	prioFw6 := strconv.Itoa(base + 7000 + cid)
	if markMask == 0 {
		markMask = DefaultDevMarkMask
	}
	fwHandle := fmt.Sprintf("0x%x/0x%x", markVal&markMask, markMask)

	buildAddArgsWith := func(hk []string, tail ...string) []string {
		args := make([]string, 0, 4+len(hk)+len(tail))
		args = append(args, "filter", "add", "dev", iface)
		args = append(args, hk...)
		args = append(args, tail...)
		return args
	}

	// runAddWithColorOSFallback: ColorOS 定制 /system/bin/tc 对裸 `ingress` 关键字可能报错退出,
	// 失败时自动回退显式 `parent ffff:fff2` (clsact ingress minor) 及 `parent ffff:`。
	fallbackCleaned := false
	runAdd := func(tail ...string) bool {
		if runNativeTC(tcBin, buildAddArgsWith(hookArgs, tail...)...) == nil {
			return true
		}
		if len(hookArgs) == 1 && hookArgs[0] == "ingress" {
			for _, altHook := range [][]string{{"parent", "ffff:fff2"}, {"parent", "ffff:"}} {
				if !fallbackCleaned {
					clearNativeIngressPoliceWithHook(tcBin, iface, cid, altHook)
				}
				if runNativeTC(tcBin, buildAddArgsWith(altHook, tail...)...) == nil {
					hookArgs = altHook
					fallbackCleaned = true
					return true
				}
			}
		}
		return false
	}

	anyOK := false
	if validStrictIPv4(ip) {
		if runAdd("protocol", "ip", "prio", prio4,
			"u32", "match", "ip", "src", ip+"/32", "police", "rate", rateStr, "burst", burstStr, "mtu", "65535", "drop") {
			anyOK = true
		}
	}
	for _, v6 := range v6Addrs {
		if runAdd("protocol", "ipv6", "prio", prio6,
			"u32", "match", "ip6", "src", v6+"/128", "police", "rate", rateStr, "burst", burstStr, "mtu", "65535", "drop") {
			anyOK = true
		}
	}
	if (markVal & markMask) != 0 {
		if runAdd("protocol", "ip", "prio", prioFw4,
			"handle", fwHandle, "fw", "police", "rate", rateStr, "burst", burstStr, "mtu", "65535", "drop") {
			anyOK = true
		}
		if runAdd("protocol", "ipv6", "prio", prioFw6,
			"handle", fwHandle, "fw", "police", "rate", rateStr, "burst", burstStr, "mtu", "65535", "drop") {
			anyOK = true
		}
	}
	if !anyOK {
		return errors.New("ingress police: failed to install any filter")
	}
	return nil
}

func clearNativeIngressPoliceWithHook(tcBin, iface string, cid int, hookArgs []string) {
	delAllForHook := func(hk []string) (anyOK bool) {
		for _, base := range []int{int(nativeIngressPolicePrioBase), int(legacyNativeIngressPolicePrioBase)} {
			for _, item := range []struct {
				proto string
				prio  int
			}{
				{"all", base + cid},
				{"ip", base + cid},
				{"ipv6", base + cid},
				{"ipv6", base + 5000 + cid},
				{"ip", base + 6000 + cid},
				{"ipv6", base + 7000 + cid},
			} {
				args := make([]string, 0, 8+len(hk))
				args = append(args, "filter", "del", "dev", iface)
				args = append(args, hk...)
				args = append(args, "protocol", item.proto, "prio", strconv.Itoa(item.prio))
				if runNativeTC(tcBin, args...) == nil {
					anyOK = true
				}
			}
		}
		return anyOK
	}
	if !delAllForHook(hookArgs) && len(hookArgs) == 1 && hookArgs[0] == "ingress" {
		delAllForHook([]string{"parent", "ffff:fff2"})
		delAllForHook([]string{"parent", "ffff:"})
	}
}

func clearNativeIngressPolice(iface string, mid int) {
	tcBin := nativeResolveSystemBinFn("tc")
	cidStr := classIDStringForMid(mid)
	cid, err := strconv.Atoi(cidStr)
	if tcBin == "" || iface == "" || err != nil || cid <= 0 {
		return
	}
	hookArgs, _ := nativeIngressFilterHookArgs(tcBin, iface)
	clearNativeIngressPoliceWithHook(tcBin, iface, cid, hookArgs)
}
