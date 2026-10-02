package main

import (
	"net"
	"testing"
	"time"

	"hnc.io/dpid/capture"
	"hnc.io/dpid/output"
)

func TestRecordFlowFPDirection(t *testing.T) {
	old := flowLog
	defer func() { flowLog = old }()
	flowLog = output.NewFlowLog()
	flowLog.SetPath(t.TempDir() + "/dpi_flows.json")
	now := time.Now()
	ev := capture.Event{Kind: capture.EventTLSClientHello, Time: now,
		SrcIP: net.ParseIP("192.168.43.7"), DstIP: net.ParseIP("203.0.113.4"), SrcPort: 41000, DstPort: 443,
		ClientIP: net.ParseIP("192.168.43.7"), RemoteIP: net.ParseIP("203.0.113.4"),
		TLS: capture.TLSInfo{JA4: "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", ALPN: []string{"h2"}}}
	recordFlowFP(ev, "aa:bb:cc:00:00:01", "192.168.43.7", "203.0.113.4")
	ev.TLS.JA4 = "" // 无指纹不记
	ev.SrcPort = 41001
	recordFlowFP(ev, "aa:bb:cc:00:00:01", "192.168.43.7", "203.0.113.4")
	s := flowLog.Snapshot(now)
	if len(s) != 1 || s[0].Sport != 41000 || s[0].Dport != 443 || s[0].Proto != "tcp" {
		t.Fatalf("unexpected: %+v", s)
	}
}
