// recorder_test.go — v5.29 T4: pcap 写入/读回、上限、类型过滤、请求文件。
package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeEthIP4 以太网 + IPv4 骨架帧(etherType 0x0800, 内容本身不必可解析)。
func fakeEthIP4(payloadLen int) []byte {
	f := make([]byte, 14+20+payloadLen)
	f[12] = 0x08
	f[13] = 0x00
	ip := f[14:]
	ip[0] = 0x45
	ip[2] = byte(len(ip) >> 8)
	ip[3] = byte(len(ip))
	return f
}

// fakeDNSEvent 只测过滤, 内容无关。
func fakeDNSEvent() Event { return Event{Kind: EventDNS} }

func startSessionForTest(t *testing.T, r *Recorder, minutes int) *recSession {
	t.Helper()
	if err := os.MkdirAll(r.recDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	s := r.start(minutes)
	if s == nil {
		t.Fatalf("start 失败")
	}
	t.Cleanup(func() { r.finishLocked() })
	return s
}

func TestRecorderPcapRoundTrip(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	s := startSessionForTest(t, r, 5)
	// 以太网帧: 应剥 14 字节头
	frame := fakeEthIP4(8)
	r.Offer(true, frame, fakeDNSEvent())
	// RAWIP 帧: 原样
	raw := frame[14:]
	ev := Event{Kind: EventTLSClientHello}
	r.Offer(false, raw, ev)
	// finishLocked 会把已入队的包写完并等收尾(搬运)结束 —— 不用 sleep 等
	r.finishLocked()
	if s.bytes.Load() != int64((16+len(raw))*2) {
		t.Fatalf("bytes = %d", s.bytes.Load())
	}

	// 文件搬到 exports/ 了
	ents, _ := os.ReadDir(filepath.Join(r.hncDir, "exports"))
	var pcapFile string
	for _, e := range ents {
		if isRecPcapName(e.Name()) {
			pcapFile = filepath.Join(r.hncDir, "exports", e.Name())
		}
	}
	if pcapFile == "" {
		t.Fatalf("exports/ 里没有 rec-*.pcap: %v", ents)
	}
	f, err := os.Open(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := NewPcapReader(f)
	if err != nil {
		t.Fatalf("pcap 头不对: %v", err)
	}
	if rd.Ethernet {
		t.Fatal("应是 RAW 链路")
	}
	var lens []int
	for {
		b, _, err := rd.Next()
		if err != nil {
			break
		}
		lens = append(lens, len(b))
	}
	if len(lens) != 2 {
		t.Fatalf("包数 = %d, want 2", len(lens))
	}
	if lens[0] != 28 || lens[1] != 28 {
		t.Fatalf("剥头/原样尺寸错: %v", lens)
	}
}

// readRecPackets 读 exports/ 里唯一的 rec-*.pcap, 返回各包长度。
func readRecPackets(t *testing.T, r *Recorder) []int {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(r.hncDir, "exports"))
	var lens []int
	n := 0
	for _, e := range ents {
		if !isRecPcapName(e.Name()) {
			continue
		}
		n++
		f, err := os.Open(filepath.Join(r.hncDir, "exports", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		rd, err := NewPcapReader(f)
		if err != nil {
			f.Close()
			t.Fatal(err)
		}
		for {
			b, _, err := rd.Next()
			if err != nil {
				break
			}
			lens = append(lens, len(b))
		}
		f.Close()
	}
	if n != 1 {
		t.Fatalf("exports/ 里应有 1 个 rec-*.pcap, 有 %d 个", n)
	}
	return lens
}

func TestRecorderOfferKindFilter(t *testing.T) {
	// 只有 DNS / TLS ClientHello / HTTP, 以及「正在重组的握手首段」进文件;
	// Flow / DevHint / Unknown 丢弃。(rc1 的用例在 150ms 后看队列长度 ——
	// writeLoop 早把队列消化了, 什么都没测到。)
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	startSessionForTest(t, r, 5)
	for _, k := range []EventKind{EventFlow, EventDevHint, EventUnknown} {
		r.Offer(false, make([]byte, 40), Event{Kind: k})
	}
	r.Offer(false, make([]byte, 41), Event{Kind: EventFlow, asmPending: true})
	r.finishLocked()
	if lens := readRecPackets(t, r); len(lens) != 1 || lens[0] != 41 {
		t.Fatalf("应只录到重组首段(41 字节), got %v", lens)
	}
}

// TestRecorderSizeCapInWriter 20 MB 上限由写盘协程硬卡(rc1 只靠 2 秒一次的
// pollOnce 收尾, 两次检查之间照写不误)。
func TestRecorderSizeCapInWriter(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	s := startSessionForTest(t, r, 30)
	s.bytes.Store(recMaxFileBytes - 30)
	r.Offer(false, make([]byte, 40), fakeDNSEvent()) // 16+40 > 30 → 不写
	r.finishLocked()
	if lens := readRecPackets(t, r); len(lens) != 0 {
		t.Fatalf("超过上限的包不该写入, got %v", lens)
	}
}

// TestRecorderRequestMinutesHonored 请求文件里的分钟数要生效(rc1 先删文件
// 再读, 恒为默认 10 分钟)。
func TestRecorderRequestMinutesHonored(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	t.Cleanup(r.finishLocked)
	if err := os.WriteFile(filepath.Join(r.runDir, "capture_record.request"), []byte("3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.pollTick()
	if r.sess.Load() == nil {
		t.Fatal("请求文件后应开始录制")
	}
	r.mu.Lock()
	m := r.minutes
	r.mu.Unlock()
	if m != 3 {
		t.Fatalf("minutes = %d, want 3", m)
	}
}

func TestRecorderRequestWithStopCancels(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	os.WriteFile(filepath.Join(r.runDir, "capture_record.request"), []byte("5"), 0o644)
	os.WriteFile(filepath.Join(r.runDir, "capture_record.stop"), []byte("1"), 0o644)
	r.pollTick()
	if r.sess.Load() != nil {
		t.Fatal("request 与 stop 同时在应取消")
	}
	for _, f := range []string{"capture_record.request", "capture_record.stop"} {
		if _, err := os.Stat(filepath.Join(r.runDir, f)); !os.IsNotExist(err) {
			t.Errorf("%s 应被消费", f)
		}
	}
}

func TestRecorderNonBlockingWhenFull(t *testing.T) {
	// 队列塞满后 Offer 不阻塞(直接丢): 100 次循环内返回。
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	s := startSessionForTest(t, r, 5)
	for i := 0; i < recQueueLen; i++ {
		s.queue <- recItem{}
	}
	done := make(chan struct{})
	go func() {
		r.Offer(false, make([]byte, 40), fakeDNSEvent())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Offer 被阻塞了")
	}
}

func TestRecorderStopFile(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	startSessionForTest(t, r, 30) // 30 分钟不会到时
	stop := filepath.Join(r.runDir, "capture_record.stop")
	if err := os.WriteFile(stop, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.pollOnce()
	if r.sess.Load() != nil {
		t.Fatal("stop 文件后应结束会话")
	}
	if _, err := os.Stat(stop); !os.IsNotExist(err) {
		t.Fatal("stop 文件应被消费掉")
	}
}

func TestRecorderSizeLimit(t *testing.T) {
	// 20MB 上限: 直接把 bytes 计数顶过线, pollOnce 应收尾。
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	s := startSessionForTest(t, r, 30)
	s.bytes.Store(recMaxFileBytes + 1)
	r.pollOnce()
	if r.sess.Load() != nil {
		t.Fatal("超 20MB 应结束会话")
	}
}

func TestRecorderRequestFileValidation(t *testing.T) {
	// 分钟数 1~30, 坏值默认 10; request 文件读到即删。
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	req := filepath.Join(r.runDir, "capture_record.request")
	for _, c := range []struct {
		content string
		want    int
	}{
		{"5\n", 5},
		{"99\n", recDefaultMin},
		{"abc\n", recDefaultMin},
		{"0\n", recDefaultMin},
		{"", recDefaultMin},
	} {
		os.WriteFile(req, []byte(c.content), 0o644)
		min := r.parseRequest()
		if min != c.want {
			t.Errorf("parseRequest(%q) = %d, want %d", c.content, min, c.want)
		}
		if _, err := os.Stat(req); !os.IsNotExist(err) {
			t.Errorf("request 文件没删: %q", c.content)
		}
	}
}

// TestRecorderSplitClientHelloReplayable 录制 → 回放端到端: 分两段的 Chrome
// 风格 ClientHello, 首段在解析时挂进重组表(不产出事件)。rc1 只录产出事件
// 的包, 文件里只有末段, 回放永远拼不出来。
func TestRecorderSplitClientHelloReplayable(t *testing.T) {
	resetQUICState(t)
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	startSessionForTest(t, r, 5)
	srv := [4]byte{93, 184, 216, 34}
	big := buildClientHelloRecord(extVersions, extSigAlgs, extBigKeyShare, extSNI("split.example.com"), extALPN("h2"), extGreaseTail)
	ts := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for i, pkt := range [][]byte{
		replayTCP(56001, 443, srv, 7000, big[:1000]),
		replayTCP(56001, 443, srv, 8000, big[1000:]),
	} {
		ev, _ := parseRawIPPacket(pkt, ts.Add(time.Duration(i)*10*time.Millisecond))
		r.Offer(false, pkt, ev) // 同 rawsocket: 解析后把包和事件交给录制器
	}
	r.finishLocked()
	if lens := readRecPackets(t, r); len(lens) != 2 {
		t.Fatalf("两段都该录下, got %d 个包", len(lens))
	}
	ents, _ := os.ReadDir(filepath.Join(r.hncDir, "exports"))
	f, err := os.Open(filepath.Join(r.hncDir, "exports", ents[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := NewPcapReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var sni string
	for {
		b, pts, err := rd.Next()
		if err != nil {
			break
		}
		if ev, res := ParseForReplay(b, pts, rd.Ethernet); res == ParseOK && ev.Kind == EventTLSClientHello {
			sni = ev.TLS.SNI
		}
	}
	if sni != "split.example.com" {
		t.Fatalf("回放没还原出分段 ClientHello 的 SNI, got %q", sni)
	}
}

// TestRecorderStaleStopCleared 没在录时点了「停止」留下的 stop 文件, 不能
// 把之后的录制请求直接取消。
func TestRecorderStaleStopCleared(t *testing.T) {
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	t.Cleanup(r.finishLocked)
	os.WriteFile(filepath.Join(r.runDir, "capture_record.stop"), []byte("1"), 0o644)
	r.pollTick() // 空闲: 清掉残留 stop
	os.WriteFile(filepath.Join(r.runDir, "capture_record.request"), []byte("5"), 0o644)
	r.pollTick()
	if r.sess.Load() == nil {
		t.Fatal("残留 stop 不该取消新的录制请求")
	}
}
