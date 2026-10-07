// replay_testdata_test.go — v5.29 T4: 生成 testdata/replay/*.pcap(回放回归
// 用, 全部人工合成, 不放真机录制)。
//
// 放在 capture 包里是为了复用这里现成的报文构造器(ClientHello 扩展、QUIC
// Initial 加密、RFC 9001 测试向量)。默认只校验仓库里的 pcap 与生成器输出
// 逐字节一致(改了生成器却忘了重新生成会在这里失败); 需要重新生成时:
//
//	UPDATE_TESTDATA=1 go test ./capture -run TestReplayTestdataPcaps
//	UPDATE_TESTDATA=1 go test ./cmd/dpid_replay -run TestReplayRegression
//
// 第二条重写期望输出(.expected.jsonl), 提交前人工 review diff。
//
// 覆盖: DNS 查询、单段 TLS 1.3 ClientHello、分两段的 Chrome 风格 ClientHello
// (SNI 落在第二段, 走重组)、QUIC v1 Initial(RFC 9001 A.2 向量)、跨两个
// Initial 包的 QUIC ClientHello、ECH 外层。每个文件的四元组都不同, 回放
// 进程里的重组表不会串。
package capture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var replayBaseTS = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func replayIPv4(proto byte, dst [4]byte, l4 []byte) []byte {
	ip := make([]byte, 20, 20+len(l4))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{192, 168, 43, 10})
	copy(ip[16:20], dst[:])
	return append(ip, l4...)
}

func replayUDP(sport, dport uint16, dst [4]byte, payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	return replayIPv4(17, dst, append(u, payload...))
}

// replayTCP PSH|ACK 数据段。
func replayTCP(sport, dport uint16, dst [4]byte, seq uint32, payload []byte) []byte {
	th := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(th[0:], sport)
	binary.BigEndian.PutUint16(th[2:], dport)
	binary.BigEndian.PutUint32(th[4:], seq)
	binary.BigEndian.PutUint32(th[8:], 1)
	th[12] = 5 << 4
	th[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(th[14:], 0xffff)
	return replayIPv4(6, dst, append(th, payload...))
}

func replayDNSQuery(id uint16, qname string) []byte {
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range bytes.Split([]byte(qname), []byte(".")) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// replayPcapBytes LINKTYPE_RAW(101)pcap, 包间隔 10ms。
func replayPcapBytes(pkts [][]byte) []byte {
	var buf bytes.Buffer
	var g [24]byte
	binary.LittleEndian.PutUint32(g[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(g[4:6], 2)
	binary.LittleEndian.PutUint16(g[6:8], 4)
	binary.LittleEndian.PutUint32(g[16:20], 65536)
	binary.LittleEndian.PutUint32(g[20:24], recLinkTypeRAW)
	buf.Write(g[:])
	for i, p := range pkts {
		ts := replayBaseTS.Add(time.Duration(i) * 10 * time.Millisecond)
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(p)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(p)))
		buf.Write(rh[:])
		buf.Write(p)
	}
	return buf.Bytes()
}

func replayTestdataFiles(t *testing.T) map[string][]byte {
	srv := [4]byte{93, 184, 216, 34}
	dns := [4]byte{8, 8, 8, 8}
	out := map[string][]byte{}

	// 1. DNS 查询 + 单段 TLS 1.3 ClientHello
	ch := buildClientHelloRecord(extSNI("www.example.com"), extALPN("h2", "http/1.1"), extVersions, extSigAlgs)
	out["dns-tls.pcap"] = replayPcapBytes([][]byte{
		replayUDP(44444, 53, dns, replayDNSQuery(0x1234, "example.com")),
		replayTCP(55555, 443, srv, 1000, ch),
	})

	// 2. Chrome 风格大 ClientHello(X25519MLKEM768 key_share ~1.2KB 在前, SNI
	//    在后, 结尾 GREASE)拆两段: 首段挂起等重组, 第二段拼齐产出事件。
	big := buildClientHelloRecord(extVersions, extSigAlgs, extBigKeyShare, extSNI("frag.example.com"), extALPN("h2"), extGreaseTail)
	cut := 1000
	if bytes.Contains(big[:cut], []byte("frag.example.com")) {
		t.Fatal("构造错误: SNI 应落在第二段")
	}
	out["fragmented-ch.pcap"] = replayPcapBytes([][]byte{
		replayTCP(55556, 443, srv, 5000, big[:cut]),
		replayTCP(55556, 443, srv, 5000+uint32(cut), big[cut:]),
	})

	// 3. QUIC v1 Initial(RFC 9001 A.2, SNI example.com)+ 跨两个 Initial
	//    包的 ClientHello + 带 ECH 扩展的 TLS ClientHello(外层 SNI)。
	rfc := mustHex(t, rfc9001ProtectedPacket)
	qch := buildQUICClientHello("quic2.example.com", 1400)
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	scid := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	p1 := padTo(cryptoFrame(0, qch[:900]), 1162)
	p2 := padTo(cryptoFrame(900, qch[900:]), 1162)
	pk1 := sealQUICInitial(t, quicParamsV1, dcid, scid, nil, 0, 1, p1)
	pk2 := sealQUICInitial(t, quicParamsV1, dcid, scid, nil, 1, 1, p2)
	ech := buildClientHelloRecord(extSNI("public.example.net"), extALPN("h2"), extVersions,
		tlsExt(0xfe0d, append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x07, 0x00, 0x20}, bytes.Repeat([]byte{0x44}, 32)...)))
	out["quic-ech.pcap"] = replayPcapBytes([][]byte{
		replayUDP(50001, 443, srv, rfc),
		replayUDP(50002, 443, srv, pk1),
		replayUDP(50002, 443, srv, pk2),
		replayTCP(55557, 443, srv, 9000, ech),
	})
	return out
}

func TestReplayTestdataPcaps(t *testing.T) {
	dir := filepath.Join("..", "testdata", "replay")
	files := replayTestdataFiles(t)
	if os.Getenv("UPDATE_TESTDATA") == "1" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s 缺失(UPDATE_TESTDATA=1 重新生成): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s 与生成器输出不一致(改了生成器要重新生成并更新期望输出)", name)
		}
	}
}

// TestReplayTestdataParses 生成的包真能被解析器认出来(防止合成器本身写错,
// 再把「什么都没解析出来」锁进期望文件 —— rc1 的 SNI 扩展多了 2 个字节,
// 期望文件里就只剩一行 DNS)。
func TestReplayTestdataParses(t *testing.T) {
	resetQUICState(t)
	files := replayTestdataFiles(t)
	want := map[string][]string{
		"dns-tls.pcap":       {"dns:example.com", "tls:www.example.com"},
		"fragmented-ch.pcap": {"tls:frag.example.com(reasm)"},
		"quic-ech.pcap":      {"quic:example.com", "quic:quic2.example.com", "tls:public.example.net(ech)"},
	}
	for name, b := range files {
		rd, err := NewPcapReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for {
			pkt, ts, err := rd.Next()
			if err != nil {
				break
			}
			ev, res := ParseForReplay(pkt, ts, false)
			if res != ParseOK {
				continue
			}
			switch ev.Kind {
			case EventDNS:
				got = append(got, "dns:"+ev.DNS.QName)
			case EventTLSClientHello:
				s := "tls:"
				if ev.TLS.IsQUIC {
					s = "quic:"
				}
				s += ev.TLS.SNI
				if ev.TLS.Reassembled {
					s += "(reasm)"
				}
				if ev.TLS.ECH {
					s += "(ech)"
				}
				got = append(got, s)
			}
		}
		if len(got) != len(want[name]) {
			t.Errorf("%s: got %v, want %v", name, got, want[name])
			continue
		}
		for i := range got {
			if got[i] != want[name][i] {
				t.Errorf("%s: got %v, want %v", name, got, want[name])
				break
			}
		}
	}
}
