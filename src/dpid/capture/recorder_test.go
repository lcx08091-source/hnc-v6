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
	// 等 writeLoop 消化
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.bytes.Load() >= int64((16+len(raw))*2) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.finishLocked()
	time.Sleep(100 * time.Millisecond)

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

func TestRecorderOfferKindFilter(t *testing.T) {
	// 只有 DNS / TLS ClientHello / HTTP 进队列; Flow / DevHint 丢弃。
	r := &Recorder{hncDir: t.TempDir(), runDir: t.TempDir()}
	s := startSessionForTest(t, r, 5)
	for _, k := range []EventKind{EventFlow, EventDevHint, EventUnknown} {
		r.Offer(false, make([]byte, 40), Event{Kind: k})
	}
	time.Sleep(150 * time.Millisecond)
	if got := len(s.queue); got != 0 {
		t.Fatalf("非握手事件进了队列: %d", got)
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
	r.mu.Lock()
	still := r.sess
	r.mu.Unlock()
	if still != nil {
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
	r.mu.Lock()
	still := r.sess
	r.mu.Unlock()
	if still != nil {
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
