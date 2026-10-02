package main

// flowfp.go — v6.x DPI v2: 把 ClientHello 事件按五元组记进 output.FlowLog
// (run/dpi_flows.json), 供 httpd 的指纹学习 / 无域名识别(fp_learn.go)join conntrack。

import (
	"hnc.io/dpid/capture"
	"hnc.io/dpid/output"
)

var flowLog *output.FlowLog

// recordFlowFP 只处理带 JA4 的 ClientHello(TLS / QUIC Initial)。ClientHello 总是
// 客户端发出的, 但仍按 ClientIP 判方向, 防 assignClient 以后改语义。
func recordFlowFP(ev capture.Event, clientMAC, clientIP, remoteIP string) {
	if flowLog == nil || ev.TLS.JA4 == "" {
		return
	}
	sport, dport := int(ev.SrcPort), int(ev.DstPort)
	if ev.SrcIP != nil && ev.ClientIP != nil && !ev.SrcIP.Equal(ev.ClientIP) {
		sport, dport = dport, sport
	}
	flowLog.Record(clientMAC, clientIP, sport, remoteIP, dport, ev.IsUDP, ev.TLS.JA4, ev.TLS.ALPN, ev.TLS.SNI, ev.Time)
}
