package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// v5.27 T2: dpi_flows.json / label_samples 的 qtp 是可选字段 —— 有就写、旧行照常解析。
func TestFlowLogQTPRoundTrip(t *testing.T) {
	l := testFlowLog(t)
	now := time.Unix(1_700_000_000, 0)
	qtp := "qtp1_0123456789ab"
	l.RecordQTP("m", "10.0.0.2", 4000, "198.51.100.1", 443, true, "q13d0310h3_c_d", []string{"h3"}, "", qtp, now)
	l.RecordQTP("m", "10.0.0.2", 4001, "198.51.100.1", 443, false, "t13d_x_y", nil, "", qtp, now)       // TCP 不带 qtp
	l.RecordQTP("m", "10.0.0.2", 4002, "198.51.100.1", 443, true, "q13d_x_y", nil, "", "qtp1_BAD", now) // 形状不对丢弃
	got := l.Snapshot(now)
	if len(got) != 3 || got[0].QTP != qtp || got[1].QTP != "" || got[2].QTP != "" {
		t.Fatalf("records: %+v", got)
	}
	b, _ := json.Marshal(got[1])
	if strings.Contains(string(b), "qtp") {
		t.Fatalf("无 qtp 时应省略字段: %s", b)
	}
	b, _ = json.Marshal(got[0])
	var back FlowRecord
	if err := json.Unmarshal(b, &back); err != nil || back.QTP != qtp {
		t.Fatalf("round trip: %s %+v %v", b, back, err)
	}
	// 旧行(无 qtp 字段)照常解析
	old := `{"seq":1,"ts":1700000000,"cip":"10.0.0.2","sport":1,"dip":"1.1.1.1","dport":443,"proto":"udp","ja4":"q13d_a_b"}`
	var o FlowRecord
	if err := json.Unmarshal([]byte(old), &o); err != nil || o.QTP != "" || o.JA4 != "q13d_a_b" {
		t.Fatalf("old line: %+v %v", o, err)
	}
}

func TestLabelSampleQTP(t *testing.T) {
	w := lsvNew(t)
	w.Observe(LabelSampleInput{Time: lsvDay1, UID: 10234, Pkg: "com.a", SNI: "a.example.com",
		JA4: "q13d0310h3_c_d", DPort: 443, QUIC: true, QTP: "qtp1_0123456789ab", RIP: "1.1.1.1"})
	w.Observe(LabelSampleInput{Time: lsvDay1, UID: 10234, Pkg: "com.a", SNI: "b.example.com",
		JA4: "t13d_x_y", DPort: 443, QTP: "qtp1_0123456789ab", RIP: "1.1.1.1"}) // 非 QUIC 不记
	for {
		select {
		case s := <-w.ch:
			w.handle(s)
		default:
			goto done
		}
	}
done:
	lines := lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))
	if len(lines) != 2 {
		t.Fatalf("lines=%v", lines)
	}
	var a, b LabelSample
	_ = json.Unmarshal([]byte(lines[0]), &a)
	_ = json.Unmarshal([]byte(lines[1]), &b)
	if a.QTP != "qtp1_0123456789ab" || b.QTP != "" || strings.Contains(lines[1], "qtp") {
		t.Fatalf("a=%+v b=%s", a, lines[1])
	}
	var old LabelSample
	if err := json.Unmarshal([]byte(`{"ts":1,"pkg":"p","uid":10001,"sni":"s","ja4":"j","dport":443,"quic":true,"ech":false,"partial":false,"rip":"1.1.1.1"}`), &old); err != nil || old.QTP != "" {
		t.Fatalf("old: %v", err)
	}
}
