// replay_test.go — v5.29 T4: 合成 pcap 的回放回归。
//
// testdata/replay/*.pcap 由 capture/replay_testdata_test.go 生成(人工合成,
// 不放真机录制; 覆盖 DNS、TLS 1.3 ClientHello、分段 ClientHello 重组、
// QUIC v1 Initial(单包 / 跨两包)、ECH 外层)。本文件逐行比对回放输出与
// .expected.jsonl。改解析器导致输出变化时:
//
//	UPDATE_TESTDATA=1 go test ./cmd/dpid_replay -run TestReplayRegression
//
// 重写期望文件, 并在提交说明里解释为什么变。
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hnc.io/dpid/capture"
)

var replayFiles = []string{"dns-tls.pcap", "fragmented-ch.pcap", "quic-ech.pcap"}

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
	update := os.Getenv("UPDATE_TESTDATA") == "1"
	for _, f := range replayFiles {
		got, err := runReplayFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if update {
			if err := os.WriteFile(filepath.Join(dir, f+".expected.jsonl"), []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		exp, err := os.ReadFile(filepath.Join(dir, f+".expected.jsonl"))
		if err != nil {
			t.Fatalf("期望文件缺失(%s): %v", f, err)
		}
		if got != string(exp) {
			t.Errorf("%s 输出与期望不一致:\n--- got ---\n%s\n--- want ---\n%s", f, got, exp)
		}
	}
}

// TestReplayExpectedFloor 期望文件本身的底线: 每个合成场景的关键事实必须在
// (rc1 的期望文件把「TLS 一条没解析出来」锁成了正确答案: dns-tls 只有一行
// DNS, fragmented-ch 是空文件)。
func TestReplayExpectedFloor(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "replay")
	need := map[string][]string{
		"dns-tls.pcap":       {`"kind":"dns","dns":"example.com"`, `"kind":"tls","sni":"www.example.com"`, `"ja4":"t13d`},
		"fragmented-ch.pcap": {`"sni":"frag.example.com"`, `"reassembled":true`},
		"quic-ech.pcap":      {`"kind":"quic","sni":"example.com"`, `"kind":"quic","sni":"quic2.example.com"`, `"sni":"public.example.net"`, `"ech":true`},
	}
	for _, f := range replayFiles {
		exp, err := os.ReadFile(filepath.Join(dir, f+".expected.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range need[f] {
			if !strings.Contains(string(exp), s) {
				t.Errorf("%s 的期望输出缺 %s:\n%s", f, s, exp)
			}
		}
	}
}

