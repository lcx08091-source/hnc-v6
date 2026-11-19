// dataplane_netlink_test.go — HNC v5.40.0 T3: 原生 RTNetlink 编解码、速率表、防火墙流与 rulesStore 并发原子存储完整单测。
//
// 严格遵守 CI 防呆铁律: 100% encoding/binary.LittleEndian 逐字节合成测试向量, 零 unsafe.Pointer。

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── 测试报文合成器（避免与 ct_events_test.go 中 nla / nest 辅助函数重名） ─────────

type synthTCClassSpec struct {
	ifIndex    int
	handle     uint32
	parent     uint32
	kind       string
	rate32     uint32
	ceil32     uint32
	rate64     uint64
	ceil64     uint64
	withRate64 bool
	buffer     uint32
	cbuffer    uint32
	quantum    uint32
	level      uint32
	prio       uint32
	sentBytes  uint64
	sentPkts   uint32
	sentPkts64 uint64
	withPkt64  bool
	qlen       uint32
	backlog    uint32
	drops      uint32
	requeues   uint32
	overlimits uint32
	nestedFlag bool
}

func testRTNLEncodeClassMsg(seq uint32, sp synthTCClassSpec) []byte {
	var opt [rtnlHtbOptSize]byte
	opt[0] = 3
	opt[1] = rtnlLinkLayerEth
	binary.LittleEndian.PutUint16(opt[4:6], 0xffff)
	binary.LittleEndian.PutUint32(opt[8:12], sp.rate32)
	opt[12] = 3
	opt[13] = rtnlLinkLayerEth
	binary.LittleEndian.PutUint16(opt[16:18], 0xffff)
	binary.LittleEndian.PutUint32(opt[20:24], sp.ceil32)
	binary.LittleEndian.PutUint32(opt[24:28], sp.buffer)
	binary.LittleEndian.PutUint32(opt[28:32], sp.cbuffer)
	binary.LittleEndian.PutUint32(opt[32:36], sp.quantum)
	binary.LittleEndian.PutUint32(opt[36:40], sp.level)
	binary.LittleEndian.PutUint32(opt[40:44], sp.prio)

	var htbOpts []byte
	htbOpts = rtnlPutAttr(htbOpts, rtnlTcaHtbParms, opt[:])
	if sp.withRate64 {
		htbOpts = rtnlPutAttrU64(htbOpts, rtnlTcaHtbRate64, sp.rate64)
		htbOpts = rtnlPutAttrU64(htbOpts, rtnlTcaHtbCeil64, sp.ceil64)
	}

	// struct gnet_stats_basic: 16B (8B bytes + 4B packets + 4B tail pad)
	var basic [16]byte
	binary.LittleEndian.PutUint64(basic[0:8], sp.sentBytes)
	binary.LittleEndian.PutUint32(basic[8:12], sp.sentPkts)

	var queue [20]byte
	binary.LittleEndian.PutUint32(queue[0:4], sp.qlen)
	binary.LittleEndian.PutUint32(queue[4:8], sp.backlog)
	binary.LittleEndian.PutUint32(queue[8:12], sp.drops)
	binary.LittleEndian.PutUint32(queue[12:16], sp.requeues)
	binary.LittleEndian.PutUint32(queue[16:20], sp.overlimits)

	var stats2 []byte
	stats2 = rtnlPutAttr(stats2, rtnlTcaStatsBasic, basic[:])
	if sp.withPkt64 {
		stats2 = rtnlPutAttrU64(stats2, rtnlTcaStatsPkt64, sp.sentPkts64)
	}
	stats2 = rtnlPutAttr(stats2, rtnlTcaStatsQueue, queue[:])

	optType := uint16(rtnlTcaOptions)
	st2Type := uint16(rtnlTcaStats2)
	if sp.nestedFlag {
		optType |= nlaFNested
		st2Type |= nlaFNested
	}

	var attrs []byte
	if sp.kind != "" {
		attrs = rtnlPutAttrString(attrs, rtnlTcaKind, sp.kind)
	}
	attrs = rtnlPutAttr(attrs, optType, htbOpts)
	attrs = rtnlPutAttr(attrs, st2Type, stats2)

	return rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, seq, sp.ifIndex, sp.handle, sp.parent, 0, attrs)
}

func testRTNLEncodeDone(seq uint32) []byte {
	b := make([]byte, rtnlMsgHdrLen+4)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:6], rtnlMsgDone)
	binary.LittleEndian.PutUint16(b[6:8], rtnlFMulti)
	binary.LittleEndian.PutUint32(b[8:12], seq)
	return b
}

func testRTNLEncodeError(seq uint32, negErrno int32) []byte {
	b := make([]byte, rtnlMsgHdrLen+4+rtnlMsgHdrLen)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:6], rtnlMsgError)
	binary.LittleEndian.PutUint32(b[8:12], seq)
	binary.LittleEndian.PutUint32(b[16:20], uint32(negErrno))
	return b
}

// ── 1. parseTCClassDumpMsgs 完整单测（多类、64位计数、丢包计数、截断防御、NLMSG_ERROR） ──

func TestParseTCClassDumpMsgsMultiClassAnd64BitCounters(t *testing.T) {
	const wantIf = 9
	var stream []byte

	// 1:1 根父类 (>4 GiB/s 64-bit 速率 + >4 GiB 字节计数 + NLA_F_NESTED 嵌套位)
	stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
		ifIndex:    wantIf,
		handle:     0x00010001,
		parent:     0x00010000,
		kind:       "htb",
		rate32:     math.MaxUint32,
		ceil32:     math.MaxUint32,
		rate64:     5_000_000_000, // 40 Gbit/s = 5 GB/s (> uint32 上限)
		ceil64:     5_000_000_000,
		withRate64: true,
		buffer:     320000,
		cbuffer:    320000,
		quantum:    60000,
		level:      2,
		sentBytes:  0x0000001289abcdef, // ~79.6 GiB
		sentPkts:   0x12345678,
		sentPkts64: 0x0000000212345678,
		withPkt64:  true,
		nestedFlag: true,
	})...)

	// 1:5 普通设备类 (mid=5, 10 Mbit/s = 1,250,000 B/s, 含丢包与超限计数)
	stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
		ifIndex:    wantIf,
		handle:     0x00010005,
		parent:     0x00010001,
		kind:       "htb",
		rate32:     1_250_000,
		ceil32:     1_250_000,
		buffer:     320000,
		cbuffer:    320000,
		quantum:    12500,
		prio:       3,
		sentBytes:  9_876_543_210,
		sentPkts:   7_654_321,
		qlen:       4,
		backlog:    6056,
		drops:      137,
		requeues:   2,
		overlimits: 9841,
	})...)

	// 1:100 (mid=1 特例重映射 minor=0x0100)、1:9001 (按应用限速类)、1:a015 (应用感知 QoS 子类)
	for _, tc := range []struct {
		handle uint32
		parent uint32
		rate   uint64
		drops  uint32
	}{
		{0x00010100, 0x00010001, 625_000, 12},
		{0x00019001, 0x00010005, 375_000, 45},
		{0x0001a015, 0x00010005, 500_000, 3},
		{0x00019999, 0x00010001, 125_000_000, 0},
	} {
		stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
			ifIndex:    wantIf,
			handle:     tc.handle,
			parent:     tc.parent,
			kind:       "htb",
			rate32:     uint32(tc.rate),
			ceil32:     uint32(tc.rate),
			rate64:     tc.rate,
			ceil64:     tc.rate,
			withRate64: true,
			sentBytes:  1024 * 1024,
			sentPkts:   800,
			drops:      tc.drops,
		})...)
	}

	// 干扰项 1: 其他网卡(ifindex=22)的同名 1:5 类, 必须被过滤掉
	stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
		ifIndex:   22,
		handle:    0x00010005,
		parent:    0x00010001,
		kind:      "htb",
		rate32:    999_999,
		sentBytes: 999_999_999_999,
	})...)

	// 干扰项 2: 同网卡非 htb 类 (如 hfsc), 必须被过滤掉
	stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
		ifIndex: wantIf,
		handle:  0x00020001,
		parent:  rtnlTcHRoot,
		kind:    "hfsc",
		rate32:  111_111,
	})...)

	stream = append(stream, testRTNLEncodeDone(1)...)

	got, err := parseTCClassDumpMsgs(stream, wantIf)
	if err != nil {
		t.Fatalf("parseTCClassDumpMsgs unexpected error: %v", err)
	}

	wantKeys := []string{"1:1", "1:5", "1:100", "1:9001", "1:a015", "1:9999"}
	if len(got) != len(wantKeys) {
		t.Fatalf("class count = %d, want %d; map=%+v", len(got), len(wantKeys), got)
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing expected class %q in %+v", k, got)
		}
	}

	rootCls := got["1:1"]
	if rootCls.Parent != "1:" || rootCls.RateBps != 5_000_000_000 || rootCls.CeilBps != 5_000_000_000 {
		t.Fatalf("1:1 64-bit rate mismatch: %+v", rootCls)
	}
	if rootCls.SentBytes != 0x0000001289abcdef || rootCls.SentPkts != 0x12345678 || rootCls.SentPkts64 != 0x0000000212345678 {
		t.Fatalf("1:1 64-bit byte/pkt counter mismatch: %+v", rootCls)
	}

	dev5 := got["1:5"]
	if dev5.Parent != "1:1" || dev5.RateBps != 1_250_000 || dev5.RateKbit != 10_000 {
		t.Fatalf("1:5 rate mismatch: %+v", dev5)
	}
	if dev5.SentBytes != 9_876_543_210 || dev5.SentPkts != 7_654_321 || dev5.SentPkts64 != 7_654_321 {
		t.Fatalf("1:5 counters mismatch: %+v", dev5)
	}
	if dev5.QLen != 4 || dev5.Backlog != 6056 || dev5.Drops != 137 || dev5.Requeues != 2 || dev5.Overlimits != 9841 {
		t.Fatalf("1:5 queue stats mismatch: %+v", dev5)
	}

	if got["1:a015"].Parent != "1:5" || got["1:9001"].Parent != "1:5" || got["1:100"].Drops != 12 {
		t.Fatalf("hierarchical child classes mismatch: 1:a015=%+v 1:9001=%+v 1:100=%+v", got["1:a015"], got["1:9001"], got["1:100"])
	}
}

func TestParseTCClassDumpMsgsTruncationNeverPanics(t *testing.T) {
	full := append(
		testRTNLEncodeClassMsg(7, synthTCClassSpec{
			ifIndex:    3,
			handle:     0x00010005,
			parent:     0x00010001,
			kind:       "htb",
			rate32:     1_250_000,
			ceil32:     1_250_000,
			rate64:     1_250_000,
			ceil64:     1_250_000,
			withRate64: true,
			sentBytes:  123456789,
			sentPkts:   456,
			withPkt64:  true,
			sentPkts64: 456,
			drops:      9,
		}),
		testRTNLEncodeDone(7)...,
	)

	// 1. 逐字节全切面截断 (1 .. len(full)-1): 绝不允许 panic; 在首个完整消息结束前截断必须报错
	firstMsgLen := int(binary.LittleEndian.Uint32(full[0:4]))
	for cut := 1; cut < len(full); cut++ {
		_, err := parseTCClassDumpMsgs(full[:cut], 3)
		if cut < firstMsgLen && err == nil {
			t.Fatalf("cut=%d (< firstMsgLen=%d) expected truncation error, got nil", cut, firstMsgLen)
		}
	}

	// 2. 构造各种内部子属性长度畸形报文: tcmsg 过短、tca_len < 4、tc_htb_opt < 44、BASIC < 12、QUEUE < 20
	malformed := [][]byte{
		// nlmsg_len 声称 24 (< nlmsghdr 16 + tcmsg 20 = 36)
		func() []byte {
			b := make([]byte, 24)
			binary.LittleEndian.PutUint32(b[0:4], 24)
			binary.LittleEndian.PutUint16(b[4:6], rtnlNewTClass)
			return b
		}(),
		// 顶层 rtattr rta_len = 2 (< 4)
		func() []byte {
			attrs := []byte{0x02, 0x00, rtnlTcaKind, 0x00}
			return rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, 1, 3, 0x00010005, 0x00010001, 0, attrs)
		}(),
		// TCA_HTB_PARMS 只有 20B (< 44B)
		func() []byte {
			opts := rtnlPutAttr(nil, rtnlTcaHtbParms, make([]byte, 20))
			attrs := rtnlPutAttr(rtnlPutAttrString(nil, rtnlTcaKind, "htb"), rtnlTcaOptions, opts)
			return rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, 1, 3, 0x00010005, 0x00010001, 0, attrs)
		}(),
		// TCA_STATS_BASIC 只有 8B (< 12B)
		func() []byte {
			st2 := rtnlPutAttr(nil, rtnlTcaStatsBasic, make([]byte, 8))
			attrs := rtnlPutAttr(rtnlPutAttrString(nil, rtnlTcaKind, "htb"), rtnlTcaStats2, st2)
			return rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, 1, 3, 0x00010005, 0x00010001, 0, attrs)
		}(),
		// TCA_STATS_QUEUE 只有 16B (< 20B)
		func() []byte {
			st2 := rtnlPutAttr(nil, rtnlTcaStatsQueue, make([]byte, 16))
			attrs := rtnlPutAttr(rtnlPutAttrString(nil, rtnlTcaKind, "htb"), rtnlTcaStats2, st2)
			return rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, 1, 3, 0x00010005, 0x00010001, 0, attrs)
		}(),
	}
	for i, bad := range malformed {
		if _, err := parseTCClassDumpMsgs(bad, 3); err == nil {
			t.Fatalf("malformed case #%d expected error, got nil", i)
		}
	}
}

func TestParseTCClassDumpMsgsNLMsgErrorHandling(t *testing.T) {
	// 负内核错误码 (-22 = -EINVAL) 必须返回错误
	errPkt := testRTNLEncodeError(99, -22)
	if _, err := parseTCClassDumpMsgs(errPkt, 5); err == nil {
		t.Fatal("expected error on NLMSG_ERROR(-22), got nil")
	}

	// 截断的 NLMSG_ERROR (仅 16B 头, 缺 4B error 字段) 必须报错且不 panic
	shortErr := make([]byte, rtnlMsgHdrLen)
	binary.LittleEndian.PutUint32(shortErr[0:4], rtnlMsgHdrLen)
	binary.LittleEndian.PutUint16(shortErr[4:6], rtnlMsgError)
	if _, err := parseTCClassDumpMsgs(shortErr, 5); err == nil {
		t.Fatal("expected error on truncated NLMSG_ERROR, got nil")
	}

	// error == 0 (ACK) 后跟正常类消息应正常解析
	ackThenCls := append(
		testRTNLEncodeError(99, 0),
		testRTNLEncodeClassMsg(99, synthTCClassSpec{
			ifIndex:   5,
			handle:    0x00010008,
			parent:    0x00010001,
			kind:      "htb",
			rate32:    2_500_000,
			ceil32:    2_500_000,
			sentBytes: 4096,
			sentPkts:  4,
		})...,
	)
	got, err := parseTCClassDumpMsgs(ackThenCls, 5)
	if err != nil || got["1:8"].RateBps != 2_500_000 {
		t.Fatalf("ACK + class parse failed: err=%v got=%+v", err, got)
	}
}

// ── 2. psched 时钟刻度、tc_htb_opt 编码与 RTNetlink 过滤器报文验证 ──────────────

func TestHTBOptAndRateTableEncodingMatchesIproute2(t *testing.T) {
	// Linux 标准高精度时钟 /proc/net/psched: t2us=1000(0x3e8), us2t=64(0x40), clock_res=1000000(0xf4240)
	tick := pschedTickInUsecFromContent("000003e8 00000040 000f4240 3b9aca00\n")
	if math.Abs(tick-15.625) > 1e-9 {
		t.Fatalf("tick_in_usec = %v, want 15.625", tick)
	}
	if fb := pschedTickInUsecFromContent("corrupted content"); fb != pschedDefaultTickUsec {
		t.Fatalf("fallback tick = %v, want %v", fb, pschedDefaultTickUsec)
	}

	// 10 Mbit/s = 1,250,000 Bytes/s, burst = 25,600 Bytes (25 KiB):
	// xmit_usec = 1e6 * 25600 / 1250000 = 20480 us -> 20480 * 15.625 = 320000 ticks
	const rate10M = uint64(1_250_000)
	const burst25K = uint32(25600)
	opt, rtab, ctab := encodeHTBOpt(rate10M, rate10M, burst25K, burst25K, 12500, 3, tick)

	if opt[0] != 3 || opt[1] != rtnlLinkLayerEth {
		t.Fatalf("rate cell_log/linklayer = (%d,%d), want (3,1)", opt[0], opt[1])
	}
	if int16(binary.LittleEndian.Uint16(opt[4:6])) != -1 {
		t.Fatalf("rate cell_align = %d, want -1", int16(binary.LittleEndian.Uint16(opt[4:6])))
	}
	if gotRate := binary.LittleEndian.Uint32(opt[8:12]); gotRate != uint32(rate10M) {
		t.Fatalf("opt.rate.rate = %d, want %d", gotRate, rate10M)
	}
	if gotBuf := binary.LittleEndian.Uint32(opt[24:28]); gotBuf != 320000 {
		t.Fatalf("opt.buffer ticks = %d, want 320000", gotBuf)
	}
	if gotCBuf := binary.LittleEndian.Uint32(opt[28:32]); gotCBuf != 320000 {
		t.Fatalf("opt.cbuffer ticks = %d, want 320000", gotCBuf)
	}
	if gotQ := binary.LittleEndian.Uint32(opt[32:36]); gotQ != 12500 {
		t.Fatalf("opt.quantum = %d, want 12500", gotQ)
	}
	if !bytes.Equal(rtab[:], ctab[:]) {
		t.Fatal("rtab and ctab must match when rate == ceil")
	}

	// 验证 256 项 rtab 严格正数且单调不减; 最后一项 size = 256<<3 = 2048B -> 1638.4us -> floor(1638)*15.625 = 25593 ticks
	var prev uint32
	for i := 0; i < 256; i++ {
		v := binary.LittleEndian.Uint32(rtab[i*4 : i*4+4])
		if v == 0 || v < prev {
			t.Fatalf("rtab[%d] = %d invalid (prev=%d)", i, v, prev)
		}
		prev = v
	}
	if prev != 25593 {
		t.Fatalf("rtab[255] = %d, want 25593", prev)
	}

	// 验证 >4 GiB/s 时 32 位 rate 字段自动钳位到 0xffffffff, 且完整 RTM_NEWTCLASS 报文可自环被 parseTCClassDumpMsgs 解回 64 位速率
	clsMsg := buildHTBClassUpsertMsg(42, 11, rtnlHtbRootCls, 0x00010100, 6_000_000_000, 8_000_000_000, 204800, 204800, 60000, 3, tick)
	parsed, err := parseTCClassDumpMsgs(clsMsg, 11)
	if err != nil {
		t.Fatalf("roundtrip parse of buildHTBClassUpsertMsg failed: %v", err)
	}
	st100, ok := parsed["1:100"]
	if !ok || st100.RateBps != 6_000_000_000 || st100.CeilBps != 8_000_000_000 || st100.Parent != "1:1" {
		t.Fatalf("roundtrip 1:100 mismatch: %+v", st100)
	}

	// 验证 fw 掩码过滤器与 u32 src/dst 报文关键字段偏移
	fwMsg := buildFwFilterMsg(43, 11, rtnlHtbRootMaj, 1, rtnlEthPAll, 0x00051234, 0x00ff0000, 0x00010005)
	// tcm_handle 必须已按 mask 掩码剥离低 16 位 netd netId (0x00051234 & 0x00ff0000 == 0x00050000)
	if gotHandle := binary.LittleEndian.Uint32(fwMsg[24:28]); gotHandle != 0x00050000 {
		t.Fatalf("fw filter masked handle = 0x%08x, want 0x00050000", gotHandle)
	}

	u32Dn, err := buildU32IPv4FilterMsg(44, 11, rtnlHtbRootMaj, 105, net.ParseIP("192.168.43.5"), false, 0x00010005)
	if err != nil {
		t.Fatalf("buildU32IPv4FilterMsg downlink: %v", err)
	}
	u32Up, err := buildU32IPv4FilterMsg(45, 11, rtnlHtbRootMaj, 105, net.ParseIP("192.168.43.5"), true, 0x00010005)
	if err != nil {
		t.Fatalf("buildU32IPv4FilterMsg uplink: %v", err)
	}
	// 末尾 16 字节即 tc_u32_key: mask(ff ff ff ff) + val(c0 a8 2b 05) + off(16 or 12) + offmask(0)
	dnKey := u32Dn[len(u32Dn)-16:]
	upKey := u32Up[len(u32Up)-16:]
	if !bytes.Equal(dnKey[4:8], []byte{192, 168, 43, 5}) || binary.LittleEndian.Uint32(dnKey[8:12]) != 16 {
		t.Fatalf("u32 downlink key mismatch: %x", dnKey)
	}
	if !bytes.Equal(upKey[4:8], []byte{192, 168, 43, 5}) || binary.LittleEndian.Uint32(upKey[8:12]) != 12 {
		t.Fatalf("u32 uplink key mismatch: %x", upKey)
	}

	// 验证 mark_id -> classMinor 映射规则
	if m1, err := htbClassMinorForMid(1); err != nil || m1 != 0x0100 {
		t.Fatalf("mid=1 -> 0x%x, err=%v; want 0x0100", m1, err)
	}
	if m15, err := htbClassMinorForMid(15); err != nil || m15 != 0x0015 {
		t.Fatalf("mid=15 -> 0x%x, err=%v; want 0x0015", m15, err)
	}
}

// ── 3. 双栈防火墙规则流构造与测试桩护栏验证 ───────────────────────────────────

func TestFirewallPayloadsAndNativeDataplaneGuardrail(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// 1. 无 bin/hnc_constants.sh 时必须禁用原生路径, 且委托假 apply_device_rule.sh
	if useNativeDataplane(dir) {
		t.Fatal("useNativeDataplane must be false without bin/hnc_constants.sh")
	}
	callLog := filepath.Join(dir, "run", "fw_calls.log")
	stubScript := "#!/bin/sh\necho \"$*\" >> '" + callLog + "'\necho 5\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "apply_device_rule.sh"), []byte(stubScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := applyDeviceFirewallAtomic(dir, "wlan2", "AA:BB:CC:00:00:05", "192.168.43.5", 5, true, false); err != nil {
		t.Fatalf("stub applyDeviceFirewallAtomic failed: %v", err)
	}
	logged, _ := os.ReadFile(callLog)
	if strings.TrimSpace(string(logged)) != "alloc_mid aa:bb:cc:00:00:05" {
		t.Fatalf("stub script call = %q, want %q", string(logged), "alloc_mid aa:bb:cc:00:00:05")
	}

	// 2. 写入真实 bin/hnc_constants.sh 后启用(Linux 下为 true), 写入 run/native_dp.disabled 后立即熔断关闭
	if err := os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"), []byte("HNC_MARK_BASE=0x800000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "native_dp.disabled"), []byte("1"), 0o644)
	if useNativeDataplane(dir) {
		t.Fatal("useNativeDataplane must be false when run/native_dp.disabled exists")
	}
	_ = os.Remove(filepath.Join(dir, "run", "native_dp.disabled"))

	// 3. 校验内存构造的 *mangle 正交位域 (--set-xmark 0x00850000/0x00ff0000) 与双栈 *filter 阻断流
	v4, v6, err := buildDeviceFirewallRestorePayloads(dir, "wlan2", "aa:bb:cc:00:00:05", "192.168.43.5", 5, true, true, false)
	if err != nil {
		t.Fatalf("buildDeviceFirewallRestorePayloads: %v", err)
	}
	s4, s6 := string(v4), string(v6)
	for _, want := range []string{
		"*mangle\n:HNC_MARK - [0:0]\n",
		"-A HNC_MARK -s 192.168.43.5/32 -m mac --mac-source aa:bb:cc:00:00:05 -j MARK --set-xmark 0x00850000/0x00ff0000",
		"-A HNC_MARK -m mac --mac-source aa:bb:cc:00:00:05 -m mark --mark 0x0/0x00ff0000 -j MARK --set-xmark 0x00850000/0x00ff0000",
		"-A HNC_MARK -d 192.168.43.5/32 -j MARK --set-xmark 0x00850000/0x00ff0000",
		"*filter\n:HNC_CTRL - [0:0]\n",
		"-A HNC_CTRL -m mac --mac-source aa:bb:cc:00:00:05 -p tcp -j REJECT --reject-with tcp-reset",
		"-A HNC_CTRL -m mac --mac-source aa:bb:cc:00:00:05 -p udp --dport 443 -j DROP",
	} {
		if !strings.Contains(s4, want) {
			t.Fatalf("v4 restore payload missing %q:\n%s", want, s4)
		}
	}
	for _, want6 := range []string{
		"-A HNC_MARK -m mac --mac-source aa:bb:cc:00:00:05 -m mark --mark 0x0/0x00ff0000 -j MARK --set-xmark 0x00850000/0x00ff0000",
		"-A HNC_CTRL -m mac --mac-source aa:bb:cc:00:00:05 -p udp --dport 443 -j DROP",
	} {
		if !strings.Contains(s6, want6) {
			t.Fatalf("v6 restore payload missing %q:\n%s", want6, s6)
		}
	}
}

// ── 4. rulesStore 未知字段保留、1..99 mark_id 池、并发原子读写与假环境委托单测 ──

func TestRulesStoreConcurrentAtomicAndUnknownFields(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 放置 hnc_constants.sh 激活进程内原生存储路径
	if err := os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"), []byte("HNC_MARK_BASE=0x800000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 预置含未知顶层字段与未知设备嵌套字段的 rules.json
	seedJSON := `{
		"version": 1,
		"whitelist_mode": false,
		"custom_top_object": {"keep_me": "yes", "arr": [1, 2, 3]},
		"devices": {
			"AA:BB:CC:00:00:01": {
				"delay_ms": 45,
				"sqm_enabled": true,
				"custom_dev_note": "preserve-unknown-field"
			}
		},
		"blacklist": [],
		"whitelist": []
	}`
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(seedJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// WiFi 纯数字前导零密码必须保留为字符串
	if err := rulesStore.SetTop(dir, "hotspot_pass", "01234567"); err != nil {
		t.Fatalf("SetTop hotspot_pass: %v", err)
	}

	// 高并发读写压测: 32 个写协程 + 8 个读协程同时轰击同一 rules.json
	const workers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, workers*4)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			mac := fmt.Sprintf("aa:bb:cc:10:00:%02x", idx+1)
			ip := fmt.Sprintf("192.168.43.%d", idx+10)
			for round := 0; round < 10; round++ {
				mid, err := rulesStore.UpdateDeviceLimit(dir, mac, ip, fmt.Sprintf("%d.5", idx+1), "2", true)
				if err != nil {
					errCh <- err
					return
				}
				if mid < 1 || mid > 99 {
					errCh <- fmt.Errorf("invalid mid %d for %s", mid, mac)
					return
				}
				if idx%2 == 0 {
					if err := rulesStore.SetBlacklist(dir, mac, round%2 == 0); err != nil {
						errCh <- err
						return
					}
				} else {
					if _, err := rulesStore.SetDeviceAppQoS(dir, mac, true); err != nil {
						errCh <- err
						return
					}
				}
			}
		}(i)
	}

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				snap, err := rulesStore.ReadAll(dir)
				if err != nil {
					errCh <- err
					return
				}
				if snap["devices"] == nil {
					errCh <- fmt.Errorf("nil devices in snapshot")
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent rulesStore error: %v", err)
	}

	// 更新预置设备 aa:bb:cc:00:00:01, 验证大写键归一化 + 未知字段 100% 无损保留
	if _, err := rulesStore.UpdateDeviceLimit(dir, "aa:bb:cc:00:00:01", "192.168.43.2", "12.5", "4", true); err != nil {
		t.Fatalf("UpdateDeviceLimit seed mac: %v", err)
	}

	dm, ok, err := rulesStore.GetDeviceMap(dir, "aa:bb:cc:00:00:01")
	if err != nil || !ok {
		t.Fatalf("GetDeviceMap seed mac: ok=%v err=%v", ok, err)
	}
	if anyToRuleString(dm["custom_dev_note"]) != "preserve-unknown-field" || anyToRuleInt(dm["delay_ms"]) != 45 || !anyToRuleBool(dm["sqm_enabled"]) {
		t.Fatalf("unknown device fields lost: %+v", dm)
	}

	root, err := rulesStore.ReadAll(dir)
	if err != nil {
		t.Fatalf("ReadAll final: %v", err)
	}
	customTop, ok := root["custom_top_object"].(map[string]interface{})
	if !ok || anyToRuleString(customTop["keep_me"]) != "yes" {
		t.Fatalf("unknown top-level object lost: %+v", root["custom_top_object"])
	}
	if pass, ok := root["hotspot_pass"].(string); !ok || pass != "01234567" {
		t.Fatalf("hotspot_pass coerced to non-string %T(%v)", root["hotspot_pass"], root["hotspot_pass"])
	}

	// 验证所有已分配 mark_id 全局唯一无碰撞, 且 data/ 目录无残留 .tmp 文件
	seenMid := map[int]string{}
	devs := root["devices"].(map[string]interface{})
	for m, raw := range devs {
		d := raw.(map[string]interface{})
		mid := anyToRuleInt(d["mark_id"])
		if mid < 1 || mid > 99 {
			t.Fatalf("device %s invalid mark_id=%d", m, mid)
		}
		if prev, dup := seenMid[mid]; dup {
			t.Fatalf("duplicate mark_id=%d shared by %s and %s", mid, prev, m)
		}
		seenMid[mid] = m
	}

	entries, _ := os.ReadDir(filepath.Join(dir, "data"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("leaked temporary file in data/: %s", e.Name())
		}
	}
}

func TestRulesStoreMarkIDExhaustionAndStubDelegation(t *testing.T) {
	// 1. 验证 1..99 满池后第 100 台设备明确报错不碰撞
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"), []byte("# native\n"), 0o644)

	for i := 1; i <= 99; i++ {
		mac := fmt.Sprintf("02:aa:bb:cc:%02x:%02x", i/256, i%256)
		if _, err := rulesStore.AllocMarkID(dir, mac); err != nil {
			t.Fatalf("alloc #%d failed: %v", i, err)
		}
	}
	if _, err := rulesStore.AllocMarkID(dir, "02:aa:bb:dd:00:01"); err == nil {
		t.Fatal("100th mark_id allocation must fail when 1..99 pool is full")
	}

	// 2. 验证单测假环境(无 hnc_constants.sh, 有假 json_set.sh)自动委托给 runBin
	fakeDir := aqFake(t, `{"devices":{}}`)
	mid, err := rulesStore.SetDeviceAppQoS(fakeDir, "AA:BB:CC:00:00:09", true)
	if err != nil || mid != 7 {
		t.Fatalf("stub SetDeviceAppQoS mid=%d err=%v, want mid=7", mid, err)
	}
	wantLog := "== json_set.sh\ndevice_get\naa:bb:cc:00:00:09\nmark_id\n" +
		"== apply_device_rule.sh\nalloc_mid\naa:bb:cc:00:00:09\n" +
		"== json_set.sh\ndevice\naa:bb:cc:00:00:09\napp_qos\ntrue\n"
	if got := aqCalls(t, fakeDir); got != wantLog {
		t.Fatalf("stub call sequence =\n%s\nwant\n%s", got, wantLog)
	}
}

func TestOrthogonalMarkAndHTBHexMinorAllMidsLocked(t *testing.T) {
	// 核查全局 32 位正交掩码互不重叠
	if (DefaultDevMarkMask & uint32(0x0000ffff)) != 0 {
		t.Fatalf("DefaultDevMarkMask 0x%08x overlaps netd low16", DefaultDevMarkMask)
	}
	if (DefaultDevMarkMask & DefaultAppQoSMarkMask) != 0 ||
		(DefaultDevMarkMask & DefaultAppLimitMarkMask) != 0 ||
		(DefaultAppQoSMarkMask & DefaultAppLimitMarkMask) != 0 {
		t.Fatal("orthogonal mark masks overlap!")
	}
	if (DefaultDevMarkMask | DefaultAppQoSMarkMask | DefaultAppLimitMarkMask) != DefaultConnmarkMask {
		t.Fatalf("union of HNC masks 0x%08x != DefaultConnmarkMask 0x%08x",
			DefaultDevMarkMask|DefaultAppQoSMarkMask|DefaultAppLimitMarkMask, DefaultConnmarkMask)
	}

	// 穷举锁死 mid = 1..99 的正交 skb->mark 公式与 iproute2 十六进制字面量 classid minor 编码
	for mid := 1; mid <= 99; mid++ {
		markVal, markMask := readDeviceMarkSpec("", mid)
		wantMark := uint32(0x00800000) | (uint32(mid) << 16)
		if markVal != wantMark || markMask != uint32(0x00ff0000) {
			t.Fatalf("mid=%d mark=(0x%08x,0x%08x), want (0x%08x,0x00ff0000)", mid, markVal, markMask, wantMark)
		}
		// 内核 cls_fw 铁律: (tcm_handle & ~mask) == 0 且 tcm_handle != 0
		if markVal == 0 || (markVal & ^markMask) != 0 {
			t.Fatalf("mid=%d violates kernel cls_fw invariant: val=0x%08x mask=0x%08x", mid, markVal, markMask)
		}

		minor, err := htbClassMinorForMid(mid)
		if err != nil {
			t.Fatalf("htbClassMinorForMid(%d) error: %v", mid, err)
		}
		// iproute2 `tc class add ... classid 1:$cid` 把十进制文本 $cid 当十六进制 minor 解析!
		shellCID := strconv.Itoa(mid)
		if mid == 1 {
			shellCID = "100"
		}
		wantMinor64, err := strconv.ParseUint(shellCID, 16, 16)
		if err != nil || minor != uint16(wantMinor64) {
			t.Fatalf("mid=%d minor=0x%04x, want 0x%04x (iproute2 classid 1:%s)", mid, minor, wantMinor64, shellCID)
		}
		gotHandleStr := formatTCHandle(rtnlHtbRootMaj | uint32(minor))
		wantHandleStr := "1:" + shellCID
		if gotHandleStr != wantHandleStr {
			t.Fatalf("mid=%d formatTCHandle=%q, want %q", mid, gotHandleStr, wantHandleStr)
		}
		if dpCID := dpClassIDForMark(mid); dpCID != wantHandleStr {
			t.Fatalf("mid=%d dpClassIDForMark=%q, want %q", mid, dpCID, wantHandleStr)
		}
	}

	// 重点锚定典型值: mid=1 -> 0x00810000 & 1:100(0x0100); mid=59 -> 0x00bb0000 & 1:59(0x0059, 绝非 0x003b/1:3b!)
	mv1, _ := readDeviceMarkSpec("", 1)
	mv59, _ := readDeviceMarkSpec("", 59)
	min59, _ := htbClassMinorForMid(59)
	if mv1 != uint32(0x00810000) || mv59 != uint32(0x00bb0000) || min59 != 0x0059 || min59 == 0x003b {
		t.Fatalf("anchor check failed: mv1=0x%08x mv59=0x%08x min59=0x%04x", mv1, mv59, min59)
	}
}

// ── 5. Wave 4 红队闭环单测: HNC_STATS 幂等补齐、二级子树保护、pref 50/51 清理与跨进程锁 ──

func TestWave4EnsureNativeIPv4StatsRuleAndHooks(t *testing.T) {
	origRunner := nativeIptCmdRunner
	origBPF := nativeBPFDirPath
	defer func() {
		nativeIptCmdRunner = origRunner
		nativeBPFDirPath = origBPF
	}()

	existing := map[string]bool{}
	var calls []string
	nativeIptCmdRunner = func(bin string, args ...string) (string, error) {
		line := bin + " " + strings.Join(args, " ")
		calls = append(calls, line)
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "-L HNC_STATS") || strings.Contains(joined, "-C FORWARD -j HNC_STATS") {
			return "", nil
		}
		if strings.Contains(joined, "-C HNC_STATS -s 192.168.43.88 -j RETURN") {
			if existing["s"] {
				return "", nil
			}
			return "Bad rule", fmt.Errorf("exit status 1")
		}
		if strings.Contains(joined, "-C HNC_STATS -d 192.168.43.88 -j RETURN") {
			if existing["d"] {
				return "", nil
			}
			return "Bad rule", fmt.Errorf("exit status 1")
		}
		if strings.Contains(joined, "-A HNC_STATS -s 192.168.43.88 -j RETURN") {
			existing["s"] = true
			return "", nil
		}
		if strings.Contains(joined, "-A HNC_STATS -d 192.168.43.88 -j RETURN") {
			existing["d"] = true
			return "", nil
		}
		return "", nil
	}

	// 第 1 次: 规则不存在 -> 先 -C 检查再在 mangle 表 HNC_STATS 链 -A 追加
	ensureNativeIPv4StatsRule("/system/bin/iptables", "192.168.43.88")
	if !existing["s"] || !existing["d"] {
		t.Fatalf("expected both -s and -d HNC_STATS rules added in mangle table, calls=%v", calls)
	}
	joinedFirst := strings.Join(calls, "\n")
	if !strings.Contains(joinedFirst, "-t mangle -A HNC_STATS -s 192.168.43.88 -j RETURN") ||
		!strings.Contains(joinedFirst, "-t mangle -A HNC_STATS -d 192.168.43.88 -j RETURN") {
		t.Fatalf("missing mangle HNC_STATS -A rules in calls:\n%s", joinedFirst)
	}
	if strings.Contains(joinedFirst, ":HNC_STATS") || strings.Contains(joinedFirst, "-t filter") {
		t.Fatalf("must never flush :HNC_STATS or use filter table:\n%s", joinedFirst)
	}

	// 第 2 次: 规则已存在 -> 只执行 -C 检查, 绝不重复 -A
	calls = nil
	ensureNativeIPv4StatsRule("/system/bin/iptables", "192.168.43.88")
	for _, c := range calls {
		if strings.Contains(c, " -A ") {
			t.Fatalf("idempotent second call must not append duplicate rule: %s", c)
		}
	}

	// 验证跨层钩子: /sys/fs/bpf/hnc 存在时触发 hnc_clsact_sync.sh, app_limits 非空时写 run/app_limit.dirty
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run", "bpf_pin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	nativeBPFDirPath = filepath.Join(dir, "bpf_pin")
	clsactMarker := filepath.Join(dir, "run", "clsact_synced")
	syncSh := "#!/bin/sh\necho ok > '" + clsactMarker + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "hnc_clsact_sync.sh"), []byte(syncSh), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "app_limits.flat"), []byte("aa:bb:cc:dd:ee:05 douyin 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HNC_TEST_MODE", "1")
	syncNativeDataplaneSideEffects(dir, "AA:BB:CC:DD:EE:05")
	if _, err := os.Stat(clsactMarker); err != nil {
		t.Fatalf("expected hnc_clsact_sync.sh to be triggered when bpf dir exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "app_limit.dirty")); err != nil {
		t.Fatalf("expected run/app_limit.dirty to be written when app_limits.flat is non-empty: %v", err)
	}
}

func TestWave4SecondaryOwnerAppLimitsAndActionDelayClear(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	mac := "aa:bb:cc:dd:ee:05"
	// 1. 验证 run/app_limits.devs、data/app_limits.flat、data/app_limits.json 均被识别为二级子树持有者
	if deviceHasSecondaryQdiscOwner(dir, "wlan2", mac, 5, nil) {
		t.Fatal("expected false when no secondary owner is configured")
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "app_limits.devs"), []byte("wlan2 100\n"), 0o644)
	if !deviceHasSecondaryQdiscOwner(dir, "wlan2", "aa:bb:cc:dd:ee:01", 1, nil) {
		t.Fatal("expected mid=1 (cid=100) in run/app_limits.devs to be recognized")
	}
	_ = os.Remove(filepath.Join(dir, "run", "app_limits.devs"))

	_ = os.WriteFile(filepath.Join(dir, "data", "app_limits.json"), []byte(`{"version":1,"items":[{"mac":"AA:BB:CC:DD:EE:05","app_id":"bilibili","down_mbps":3.5}]}`), 0o644)
	if !deviceHasSecondaryQdiscOwner(dir, "wlan2", mac, 5, nil) {
		t.Fatal("expected active item in data/app_limits.json to be recognized")
	}

	// 2. 验证其他设备触发防火墙刷新时, 仅靠 app_limits 持有 mark_id=5 的设备 HNC_MARK 不会被冲掉
	_ = os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"), []byte("HNC_MARK_BASE=0x800000\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"limit_enabled":false}}}`), 0o644)
	v4, _, err := buildDeviceFirewallRestorePayloads(dir, "wlan2", "aa:bb:cc:dd:ee:09", "192.168.43.99", 9, true, false, false)
	if err != nil {
		t.Fatalf("buildDeviceFirewallRestorePayloads: %v", err)
	}
	if !strings.Contains(string(v4), "0x00850000/0x00ff0000") {
		t.Fatalf("expected app_limits owner mid=5 HNC_MARK preserved in v4 payload:\n%s", string(v4))
	}
	_ = os.Remove(filepath.Join(dir, "bin", "hnc_constants.sh"))

	// 3. 验证 actionDelayClear 在设备无整机限速但有 app_limits 时:
	//    仅清 netem 并调 set_limit 0 0 恢复 1000mbit, 绝不调 remove / unmark!
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","online":true}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{"aa:bb:cc:dd:ee:05":{"ip":"192.168.43.55","mark_id":5,"delay_enabled":true,"delay_ms":40,"limit_enabled":false}}}`), 0o644)
	execLog := filepath.Join(dir, "run", "delay_clear_calls.log")
	writeProbe := func(name, body string) {
		p := filepath.Join(dir, "bin", name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeProbe("device_detect.sh", "echo wlan2\nexit 0\n")
	writeProbe("json_set.sh", "if [ "$1" = "device_get" ] && [ "$3" = "mark_id" ]; then echo 5; exit 0; fi\necho false\nexit 0\n")
	writeProbe("json_set_batch.sh", "echo "json_set_batch $*" >> '"+execLog+"'\nexit 0\n")
	writeProbe("tc_manager.sh", "echo "tc_manager $*" >> '"+execLog+"'\nexit 0\n")
	writeProbe("iptables_manager.sh", "echo "iptables_manager $*" >> '"+execLog+"'\nexit 0\n")

	resp := actionDelayClear(dir, map[string]string{"mac": mac})
	if !resp.OK {
		t.Fatalf("actionDelayClear failed: %+v", resp)
	}
	gotLogBytes, _ := os.ReadFile(execLog)
	gotLog := string(gotLogBytes)
	if !strings.Contains(gotLog, "tc_manager set_delay wlan2 5 0 0 0 192.168.43.55") {
		t.Fatalf("expected set_delay 0 0 0 in log:\n%s", gotLog)
	}
	if !strings.Contains(gotLog, "tc_manager set_limit wlan2 5 0 0 192.168.43.55") {
		t.Fatalf("expected set_limit 0 0 (restore 1000mbit without deleting class) in log:\n%s", gotLog)
	}
	if strings.Contains(gotLog, "tc_manager remove") || strings.Contains(gotLog, "iptables_manager unmark") {
		t.Fatalf("must NOT remove class or unmark when app_limits owns subtree:\n%s", gotLog)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "app_limit.dirty")); err != nil {
		t.Fatalf("expected app_limit.dirty after delay_clear rate reset: %v", err)
	}
}

func TestWave4FWDeleteSpecsAndCrossProcessLock(t *testing.T) {
	// 1. 验证 nlDeleteDeviceHTB 根过滤器删除规格涵盖 pref 1/3/50/51
	specs := deviceFWDeleteSpecs()
	want := map[[2]uint16]bool{
		{1, rtnlEthPAll}:  true,
		{1, rtnlEthPIP}:   true,
		{3, rtnlEthPIPv6}: true,
		{50, rtnlEthPAll}: true,
		{50, rtnlEthPIP}:  true,
		{50, rtnlEthPIPv6}: true,
		{51, rtnlEthPIPv6}: true,
	}
	for _, sp := range specs {
		delete(want, sp)
		msg := buildDelFilterMsg(7, 3, rtnlHtbRootMaj, 0x00850000, sp[0], sp[1], "fw")
		gotInfo := binary.LittleEndian.Uint32(msg[32:36])
		wantInfo := (uint32(sp[0]) << 16) | uint32(rtnlHtons(sp[1]))
		if gotInfo != wantInfo {
			t.Fatalf("spec %+v tcm_info = 0x%08x, want 0x%08x", sp, gotInfo, wantInfo)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing expected fw delete specs: %+v", want)
	}

	// 2. 验证跨进程锁在 Linux 下写 owner(pid op ts)、回收陈旧死锁并等待 gate 释放
	dir := t.TempDir()
	tcLockDir := filepath.Join(dir, "run", "tc_action.lock")
	gateDir := filepath.Join(dir, "run", "lock", "gate")
	if err := os.MkdirAll(tcLockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 预置死进程且过期 40s 的陈旧 tc_action.lock
	staleOwner := fmt.Sprintf("99999999 restore %d\n", time.Now().Unix()-40)
	_ = os.WriteFile(filepath.Join(tcLockDir, "owner"), []byte(staleOwner), 0o644)

	// 预置短暂存活的 gate 锁 (120ms 后释放)
	if err := os.MkdirAll(gateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(gateDir, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
	go func() {
		time.Sleep(120 * time.Millisecond)
		_ = os.Remove(filepath.Join(gateDir, "pid"))
		_ = os.Remove(gateDir)
	}()

	unlock, err := acquireNativeDataplaneLock(dir, "set_limit")
	if err != nil {
		t.Fatalf("acquireNativeDataplaneLock failed: %v", err)
	}
	if b, rErr := os.ReadFile(filepath.Join(tcLockDir, "owner")); rErr == nil {
		fs := strings.Fields(string(b))
		if len(fs) != 3 || fs[0] != strconv.Itoa(os.Getpid()) || fs[1] != "set_limit" {
			t.Fatalf("unexpected tc_action.lock/owner format: %q", string(b))
		}
	}
	unlock()
	if _, sErr := os.Stat(tcLockDir); sErr == nil {
		t.Fatal("tc_action.lock directory must be removed after unlock()")
	}
}
