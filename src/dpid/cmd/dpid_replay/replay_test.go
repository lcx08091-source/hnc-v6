// replay_test.go — v5.29 T4: 合成 pcap 的回放回归。
//
// testdata/replay/ 里的 pcap 与 .expected.jsonl 都由本文件的
// genSynthetic()* 生成(人工合成, 不放真机录制; 覆盖 DNS 查询、
// TLS ClientHello、分片 ClientHello 三类)。期望输出一旦变化必须解释
// 为什么变(解析器行为变更), 见提交说明。
//
// 再生成方法: go test -run TestReplayRegen -update(写回 testdata)。
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/capture"
)

// ── 合成包构造(与 capture/v518_test.go 同思路的极简版) ─────────────

func dnsQueryPacket(qname string) []byte {
	// IPv4 + UDP + 最小 DNS query(header 12 + qname + type/class)
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(qname, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // A IN
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 44444)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(q)))
	ip := ipv4Header(20+8+len(q), 17)
	pkt := append(ip, udp...)
	return append(pkt, q...)
}

func ipv4Header(total, proto int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[2] = byte(total >> 8)
	h[3] = byte(total)
	h[8] = 64
	h[9] = byte(proto)
	h[12], h[13], h[14], h[15] = 192, 168, 43, 10
	h[16], h[17], h[18], h[19] = 8, 8, 8, 8
	return h
}

func tcpPacket(src, dst uint16, seq uint32, payload []byte) []byte {
	th := make([]byte, 20)
	th[0], th[1] = byte(src>>8), byte(src)
	th[2], th[3] = byte(dst>>8), byte(dst)
	binary.BigEndian.PutUint32(th[4:8], seq)
	binary.BigEndian.PutUint32(th[8:12], seq)
	th[12] = 0x50
	th[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(th[16:18], 0xffff)
	pkt := append(ipv4Header(20+20+len(payload), 6), th...)
	return append(pkt, payload...)
}

func clientHelloRecord(sni string) []byte {
	// 与 capture/v518_test.go 的 buildClientHelloRecord/extSNI 同构
	var body []byte = []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 32)
	body = append(body, bytes.Repeat([]byte{0x22}, 32)...)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	// 扩展: SNI
	var sniExt []byte
	name := []byte(sni)
	sniBody := []byte{0, 0}
	sniBody = binary.BigEndian.AppendUint16(sniBody, uint16(len(name)+3))
	sniBody = append(sniBody, 0)
	sniBody = binary.BigEndian.AppendUint16(sniBody, uint16(len(name)))
	sniBody = append(sniBody, name...)
	sniExt = binary.BigEndian.AppendUint16(sniExt, 0) // type SNI
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniBody)))
	sniExt = append(sniExt, sniBody...)
	// ALPN(h2)
	var alpnExt []byte
	alpnBody := []byte{2, 2, 'h', '2'}
	alpnExt = binary.BigEndian.AppendUint16(alpnExt, 16)
	alpnExt = binary.BigEndian.AppendUint16(alpnExt, uint16(len(alpnBody)))
	alpnExt = append(alpnExt, alpnBody...)
	ext := append(sniExt, alpnExt...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// writePcap 把 RAW IP 包写成 pcap。
func writePcap(path string, pkts [][]byte, ts time.Time) error {
	var buf bytes.Buffer
	var g [24]byte
	binary.LittleEndian.PutUint32(g[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(g[4:6], 2)
	binary.BigEndian.PutUint16(g[6:8], 4)
	binary.LittleEndian.PutUint32(g[16:20], 65536)
	binary.LittleEndian.PutUint32(g[20:24], 101)
	buf.Write(g[:])
	for i, p := range pkts {
		var rh [16]byte
		t := ts.Add(time.Duration(i) * 10 * time.Millisecond)
		binary.LittleEndian.PutUint32(rh[0:4], uint32(t.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(t.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(p)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(p)))
		buf.Write(rh[:])
		buf.Write(p)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

var base = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func regen(t *testing.T) bool {
	return os.Getenv("UPDATE_TESTDATA") == "1"
}

func TestReplayRegen(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "replay")
	os.MkdirAll(dir, 0o755)
	// 1. dns-tls.pcap: DNS 查询 + 完整 ClientHello
	if err := writePcap(filepath.Join(dir, "dns-tls.pcap"), [][]byte{
		dnsQueryPacket("example.com"),
		tcpPacket(55555, 443, 100, clientHelloRecord("www.example.com")),
	}, base); err != nil {
		t.Fatal(err)
	}
	// 2. fragmented-ch.pcap: ClientHello 分两段
	ch := clientHelloRecord("frag.example.com")
	mid := len(ch) / 2
	if err := writePcap(filepath.Join(dir, "fragmented-ch.pcap"), [][]byte{
		tcpPacket(55556, 443, 200, ch[:mid]),
		tcpPacket(55556, 443, 200+uint32(mid), ch[mid:]),
	}, base); err != nil {
		t.Fatal(err)
	}
	if !regen(t) {
		return
	}
	// 期望文件也重写(需要人工 review diff)
	for _, f := range []string{"dns-tls.pcap", "fragmented-ch.pcap"} {
		out, err := runReplayFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, f+".expected.jsonl"), []byte(out), 0o644)
	}
}

// runReplayFile 对单个 pcap 跑 replayPcap(同 CLI 逻辑)。
func runReplayFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	rd, err := capture.NewPcapReader(f)
	if err != nil {
		return "", err
	}
	var sb bytes.Buffer
	bw := bufio.NewWriter(&sb)
	if err := replayPcap(rd, json.NewEncoder(bw)); err != nil {
		return "", err
	}
	bw.Flush()
	return sb.String(), nil
}

func TestReplayRegression(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "replay")
	for _, f := range []string{"dns-tls.pcap", "fragmented-ch.pcap"} {
		exp, err := os.ReadFile(filepath.Join(dir, f+".expected.jsonl"))
		if err != nil {
			t.Fatalf("期望文件缺失(%s), 先跑 TestReplayRegen 生成: %v", f, err)
		}
		got, err := runReplayFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if got != string(exp) {
			t.Errorf("%s 输出与期望不一致:\n--- got ---\n%s\n--- want ---\n%s", f, got, exp)
		}
	}
}
