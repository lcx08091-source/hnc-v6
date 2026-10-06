// dpid_replay — v5.29 T4: 开发机离线回放 pcap 做 DPI 回归测试。
//
// 读 pcap(录制器写的 rec-*.pcap), 逐包送进 capture 的同一套解析函数,
// 输出事件 JSON(每行一个):
//
//	{"ts":..., "kind":"dns|tls|http|quic", "sni":..., "ja4":..., "qtp":...,
//	 "alpn":[...], "dns":..., "ua":..., "ech":bool, "partial":bool,
//	 "reassembled":bool, "class":"...", "class_hit":bool}
//
// class / class_hit = SNI / DNS 名字在规则库(output.LookupHostClass,
// 与 dpid 在机分类同一入口)里的分类结果 —— 开发机上没有规则文件时恒
// miss, 字段仍输出(空), 方便真机录制的包带分类回归。
//
// 用法: dpid_replay <file.pcap> [file2.pcap ...]
// 退出码 0 = 全部解析完(包括 0 事件); 1 = 文件读不了 / 不是 pcap。
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"hnc.io/dpid/capture"
	"hnc.io/dpid/output"
)

const version = "v5.29.0-rc1"

// replayEvent JSON 行结构(字段名与文档 T4 规格一致)。
type replayEvent struct {
	Ts          string   `json:"ts"`
	Kind        string   `json:"kind"`
	SNI         string   `json:"sni,omitempty"`
	JA4         string   `json:"ja4,omitempty"`
	QTP         string   `json:"qtp,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	DNS         string   `json:"dns,omitempty"`
	UA          string   `json:"ua,omitempty"`
	ECH         bool     `json:"ech,omitempty"`
	Partial     bool     `json:"partial,omitempty"`
	Reassembled bool     `json:"reassembled,omitempty"`
	Class       string   `json:"class,omitempty"`
	ClassHit    bool     `json:"class_hit,omitempty"`
}

func kindString(ev capture.Event) string {
	switch ev.Kind {
	case capture.EventDNS:
		return "dns"
	case capture.EventTLSClientHello:
		if ev.TLS.IsQUIC {
			return "quic"
		}
		return "tls"
	case capture.EventHTTP:
		return "http"
	}
	return ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dpid_replay <file.pcap> [file2.pcap ...]")
		os.Exit(1)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	rc := 0
	for _, path := range os.Args[1:] {
		if err := replayFile(path, out); err != nil {
			fmt.Fprintf(os.Stderr, "replay: %s: %v\n", path, err)
			rc = 1
		}
	}
	os.Exit(rc)
}

func replayFile(path string, out *bufio.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd, err := capture.NewPcapReader(f)
	if err != nil {
		return err
	}
	return replayPcap(rd, json.NewEncoder(out))
}

// replayPcap 逐包解析并写 JSON 行(测试与 CLI 共用)。
func replayPcap(rd *capture.PcapReader, enc *json.Encoder) error {
	for {
		b, ts, err := rd.Next()
		if err != nil { // io.EOF
			break
		}
		ev, res := capture.ParseForReplay(b, ts, rd.Ethernet)
		if res != capture.ParseOK {
			continue
		}
		kind := kindString(ev)
		if kind == "" {
			continue
		}
		line := replayEvent{Ts: ts.UTC().Format(time.RFC3339Nano), Kind: kind}
		host := ""
		switch ev.Kind {
		case capture.EventDNS:
			line.DNS = ev.DNS.QName
			host = ev.DNS.QName
		case capture.EventTLSClientHello:
			line.SNI = ev.TLS.SNI
			line.JA4 = ev.TLS.JA4
			line.QTP = ev.TLS.QTP
			line.ALPN = ev.TLS.ALPN
			line.UA = ev.TLS.UserAgent
			line.ECH = ev.TLS.ECH
			line.Partial = ev.TLS.Partial
			line.Reassembled = ev.TLS.Reassembled
			host = ev.TLS.SNI
		case capture.EventHTTP:
			// HTTP 事件的 UA 复用 TLSInfo.UserAgent(parse.go 的字段注释)
			line.UA = ev.TLS.UserAgent
		}
		if host != "" {
			if class, hit := output.LookupHostClass(host); hit {
				line.Class, line.ClassHit = class, true
			}
		}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}
