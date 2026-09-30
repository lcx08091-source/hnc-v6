package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// ── 合成 netlink 属性的小工具 ─────────────────────────────────────────

func nla(t uint16, v []byte) []byte {
	l := 4 + len(v)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l))
	binary.LittleEndian.PutUint16(b[2:4], t)
	copy(b[4:], v)
	return b
}

func nest(t uint16, parts ...[]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	return nla(t|nlaFNested, v)
}

func be16(n uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, n); return b }
func be64(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }

func synthDestroy(src, dst string, proto uint8, sport, dport uint16, up, dn uint64, withCnt bool) []byte {
	s, d := net.ParseIP(src), net.ParseIP(dst)
	var ipAttrs []byte
	if s4 := s.To4(); s4 != nil {
		ipAttrs = append(nla(ctaIPv4Src, s4), nla(ctaIPv4Dst, d.To4())...)
	} else {
		ipAttrs = append(nla(ctaIPv6Src, s.To16()), nla(ctaIPv6Dst, d.To16())...)
	}
	p := []byte{2, 0, 0, 0} // nfgenmsg: family, version, res_id
	p = append(p, nest(ctaTupleOrig,
		nest(ctaTupleIP, ipAttrs),
		nest(ctaTupleProto, nla(ctaProtoNum, []byte{proto}), nla(ctaProtoSrcPort, be16(sport)), nla(ctaProtoDstPort, be16(dport))),
	)...)
	if withCnt {
		p = append(p, nest(ctaCountersOrig, nla(1, be64(3)), nla(ctaCountersBytes, be64(up)))...)
		p = append(p, nest(ctaCountersReply, nla(1, be64(3)), nla(ctaCountersBytes, be64(dn)))...)
	}
	return p
}

const ctDeleteType = nfnlSubsysCtnetlink<<8 | ipctnlMsgCtDelete

func TestParseCtDestroy(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ev, ok := parseCtDestroy(ctDeleteType, synthDestroy("192.168.43.12", "9.9.9.9", 6, 40000, 443, 1234, 567890, true), now)
	if !ok || !ev.HasCnt || ev.UpB != 1234 || ev.DnB != 567890 {
		t.Fatalf("parse v4 = %+v %v", ev, ok)
	}
	want := (&ctEntry{Proto: "tcp", Src: "192.168.43.12", Dst: "9.9.9.9", Sport: 40000, Dport: 443}).key()
	if ev.Key != want {
		t.Fatalf("key %q != %q (must match /proc key)", ev.Key, want)
	}
	// IPv6 走压缩格式, 与 parseConntrackLine 归一化后一致
	ev6, ok := parseCtDestroy(ctDeleteType, synthDestroy("2408:8000::12", "2400:3200::1", 17, 5353, 53, 80, 120, true), now)
	if !ok || ev6.Src != "2408:8000::12" || ev6.Key != "udp|2408:8000::12|5353|2400:3200::1|53" {
		t.Fatalf("parse v6 = %+v", ev6)
	}
	// 没开 acct: 解析成功但 HasCnt=false(记账时忽略)
	if ev, ok := parseCtDestroy(ctDeleteType, synthDestroy("192.168.43.12", "9.9.9.9", 6, 1, 2, 0, 0, false), now); !ok || ev.HasCnt {
		t.Fatalf("no-counter event = %+v %v", ev, ok)
	}
	// 其它消息类型 / 截断数据不接受
	if _, ok := parseCtDestroy(nfnlSubsysCtnetlink<<8|0, synthDestroy("1.1.1.1", "2.2.2.2", 6, 1, 2, 1, 1, true), now); ok {
		t.Fatal("IPCTNL_MSG_CT_NEW must be ignored")
	}
	if _, ok := parseCtDestroy(ctDeleteType, []byte{2, 0}, now); ok {
		t.Fatal("truncated payload accepted")
	}
	// 畸形属性长度不 panic
	bad := append([]byte{2, 0, 0, 0}, 0xff, 0x00, 0x01, 0x00)
	_, _ = parseCtDestroy(ctDeleteType, bad, now)
}

func TestAppUsageAcctStepPrecise(t *testing.T) {
	cli := "192.168.43.12"
	keep := func(src string) bool { return src == cli }
	ent := func(dst string, sport int, up, dn uint64) ctEntry {
		return ctEntry{Proto: "tcp", Src: cli, Dst: dst, Sport: sport, Dport: 443, UpB: up, DnB: dn}
	}
	dev := func(dst string, sport int, up, dn uint64, at time.Time) ctDestroy {
		e := ent(dst, sport, 0, 0)
		return ctDestroy{Key: e.key(), Src: cli, Dst: dst, UpB: up, DnB: dn, HasCnt: true, At: at}
	}
	sum := func(ds []appUsageDelta) (u, d uint64) {
		for _, x := range ds {
			u += x.Up
			d += x.Dn
		}
		return
	}
	var prev map[string][2]uint64
	init := false
	t0 := time.Unix(1_800_000_000, 0)

	// 第 0 轮: 基线; 基线前收到的事件一律丢弃(不知道它们之前算过多少)
	out := appUsageAcctStep(&prev, &init, []ctEntry{ent("9.9.9.9", 1000, 5000, 100000), ent("8.8.8.8", 1001, 10, 10)},
		t0, []ctDestroy{dev("7.7.7.7", 999, 1e6, 1e6, t0.Add(-time.Second))}, keep)
	if len(out) != 0 || !init {
		t.Fatalf("baseline must count nothing: %+v", out)
	}

	// 第 1 轮(t0+10s):
	//  - 9.9.9.9:1000 快照后又长了 → 在快照里正常差分
	//  - 8.8.8.8:1001 在 t0+5s 结束, 最终 (40, 70) → 尾巴 (30, 60), 不在本轮快照
	//  - 6.6.6.6:1002 在两次采样之间开始又结束 → 全部 (500, 9000)
	//  - 非本机设备的事件忽略
	t1 := t0.Add(10 * time.Second)
	evs := []ctDestroy{
		dev("8.8.8.8", 1001, 40, 70, t0.Add(5*time.Second)),
		dev("6.6.6.6", 1002, 500, 9000, t0.Add(6*time.Second)),
		{Key: "tcp|10.0.0.9|1|1.1.1.1|443", Src: "10.0.0.9", Dst: "1.1.1.1", UpB: 1e9, DnB: 1e9, HasCnt: true, At: t0.Add(time.Second)},
	}
	out = appUsageAcctStep(&prev, &init, []ctEntry{ent("9.9.9.9", 1000, 6000, 300000)}, t1, evs, keep)
	if u, d := sum(out); u != 1000+30+500 || d != 200000+60+9000 {
		t.Fatalf("round1 up=%d down=%d (%+v)", u, d, out)
	}

	// 第 2 轮(t1+10s): 竞态 —— 快照在 t2 读出了 9.9.9.9:1000 (7000, 400000),
	// 但它在快照开始之后(t2+0.3s)才被销毁, 最终 (7500, 450000)。
	// 应记: 事件尾巴 = 最终 − 上轮快照 (1500, 150000); 快照里的旧读数必须跳过(否则重复)。
	t2 := t1.Add(10 * time.Second)
	out = appUsageAcctStep(&prev, &init, []ctEntry{ent("9.9.9.9", 1000, 7000, 400000)}, t2,
		[]ctDestroy{dev("9.9.9.9", 1000, 7500, 450000, t2.Add(300*time.Millisecond))}, keep)
	if u, d := sum(out); u != 1500 || d != 150000 {
		t.Fatalf("round2 (stale snapshot) up=%d down=%d", u, d)
	}
	if _, still := prev["tcp|"+cli+"|1000|9.9.9.9|443"]; still {
		t.Fatal("dead connection must not stay in prev")
	}

	// 第 3 轮: 同五元组在销毁后(快照开始前)被重新建立 → 按新连接记全部, 不与旧的混
	t3 := t2.Add(10 * time.Second)
	out = appUsageAcctStep(&prev, &init, []ctEntry{ent("9.9.9.9", 1000, 100, 200)}, t3,
		[]ctDestroy{dev("9.9.9.9", 1000, 7600, 450100, t3.Add(-2*time.Second))}, keep)
	// 上轮已用事件把旧连接结清并从 prev 删掉; 本轮这条事件是同 key 的另一条连接
	// (从没被快照看到过)→ 记全部字节; 快照里的 (100,200) 是事件之后新建的第三条
	// 连接(事件早于快照开始)→ 也记全部。
	if u, d := sum(out); u != 7600+100 || d != 450100+200 {
		t.Fatalf("round3 key reuse up=%d down=%d", u, d)
	}

	// 第 4 轮: 无事件(订阅不可用)→ 与旧的纯轮询口径完全一致
	t4 := t3.Add(10 * time.Second)
	out = appUsageAcctStep(&prev, &init, []ctEntry{ent("9.9.9.9", 1000, 150, 260)}, t4, nil, keep)
	if u, d := sum(out); u != 50 || d != 60 {
		t.Fatalf("round4 polling-only up=%d down=%d", u, d)
	}

	// 第 5 轮: 同一连接的事件重复到达(不应发生, 但要防): 第二条不在 prev → 会被当新连接;
	// 这里验证最常见的"单条事件 + 快照已无此连接"只记一次尾巴。
	t5 := t4.Add(10 * time.Second)
	out = appUsageAcctStep(&prev, &init, nil, t5, []ctDestroy{dev("9.9.9.9", 1000, 170, 300, t4.Add(3*time.Second))}, keep)
	if u, d := sum(out); u != 20 || d != 40 {
		t.Fatalf("round5 tail up=%d down=%d", u, d)
	}
	out = appUsageAcctStep(&prev, &init, nil, t5.Add(10*time.Second), nil, keep)
	if len(out) != 0 {
		t.Fatalf("idle round must add nothing: %+v", out)
	}
}
