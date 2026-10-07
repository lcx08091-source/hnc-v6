// recorder.go — v5.29 T4: 流量录制(只录已被解析成事件的握手类原始包)。
//
// 开关: run/capture_record.request(内容 = 录制分钟数, 1~30, 默认 10)。
// dpid 看到后开始把 DNS / TLS ClientHello(含 QUIC Initial)/ HTTP 请求头
// 事件对应的原始包写成标准 pcap(LINKTYPE_RAW=101, 以太网帧剥掉 14 字节
// 头只留 IP 包):
//
//	run/capture_rec/rec-YYYYMMDD-HHMMSS.pcap
//
// 停止条件: 到时(分钟数)、单文件 20 MB、run/capture_record.stop 出现。
// 到时/到量即停并删除请求文件; 结束后整个文件移到 <hnc>/exports/(名字
// 保持 rec-*.pcap, /api/exports 需认这个名字)。
//
// 写盘在后台 goroutine; 抓包回调里只做非阻塞入队(select default 丢弃,
// 照 label_samples.go 的做法)。没在录时 Offer 只是一次原子读(不持锁)。
//
// 除了已产出事件的包, 还录「正在重组的握手首段」(Event.asmPending: TCP
// ClientHello 首段挂进重组表 / QUIC Initial 还没凑齐 CRYPTO 流)——
// Chrome 带 X25519MLKEM768 的 ClientHello 必然拆两段, 只录产出事件的末段
// 的话, 回放拼不出来。状态写 run/capture_rec/status.json
// {recording, started_at, minutes, bytes, path}(前端显示用)。
//
// 隐私边界(硬约束): 只录这四类事件的包, 不录完整流量; 界面提示
// 「录制内容包含连接设备访问的域名, 只存本机、请勿随意分享」。
package capture

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	recLinkTypeRAW   = 101
	recQueueLen      = 1024
	recMaxFileBytes  = 20 << 20
	recStatusEvery   = 2 * time.Second
	recPollEvery     = 2 * time.Second
	recIdlePollEvery = 10 * time.Second
	recDefaultMin    = 10
	recMaxMinutes    = 30
	recEthernetBytes = 14
)

// ethertype v4/v6(剥以太网头时校验)。
var ethTypes = map[uint16]bool{0x0800: true, 0x86dd: true}

// DefaultRecorder dpid main 里 NewRecorder 后存进来(rawsocket 的热路径
// 只做一次原子 Load, 不持锁)。
var DefaultRecorder atomic.Value

// Recorder 全进程一个(dpid main 创建并启动)。
type Recorder struct {
	hncDir string // exports/ 的根
	runDir string // run/

	mu   sync.Mutex
	sess atomic.Pointer[recSession] // 热路径只做 Load; 起停在 mu 内

	startedAt time.Time
	minutes   int
}

type recSession struct {
	path     string
	f        *os.File
	queue    chan recItem
	done     chan struct{} // 关 = 停止
	finished chan struct{} // writeLoop 收尾(落盘 + 搬运)完成后关
	bytes    atomic.Int64
}

type recItem struct {
	data []byte
	ts   time.Time
}

// NewRecorder 创建并启动轮询循环(请求文件 / 到时 / stop)。
func NewRecorder(hncDir, runDir string) *Recorder {
	r := &Recorder{hncDir: hncDir, runDir: runDir}
	go r.pollLoop()
	return r
}

// Offer 抓包回调里调用(非阻塞, 判不了/满了就丢)。ethernet = 链路是以太网
// (需要剥 14 字节头); RAWIP/NONE 直接是 IP 包。ev 由调用方已解析好 ——
// 只录握手类事件。
func (r *Recorder) Offer(ethernet bool, frame []byte, ev Event) {
	s := r.sess.Load()
	if s == nil {
		return
	}
	switch ev.Kind {
	case EventDNS, EventTLSClientHello, EventHTTP:
	default:
		if !ev.asmPending { // 正在重组的握手首段也要(否则回放拼不出分段 ClientHello)
			return
		}
	}
	data := frame
	if ethernet {
		if len(frame) < recEthernetBytes {
			return
		}
		et := binary.BigEndian.Uint16(frame[12:14])
		if !ethTypes[et] {
			return
		}
		data = frame[recEthernetBytes:]
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case s.queue <- recItem{data: buf, ts: time.Now()}:
	default:
		// 满了就丢 —— 录制是采样性质的, 不能反过来阻塞抓包路径
	}
}

// Status 当前录制状态(前端显示)。
func (r *Recorder) Status() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sess.Load()
	st := map[string]interface{}{"recording": false}
	if s != nil {
		st["recording"] = true
		st["started_at"] = r.startedAt.Unix()
		st["minutes"] = r.minutes
		st["bytes"] = s.bytes.Load()
		st["path"] = s.path
	}
	return st
}

func (r *Recorder) statusFile() string { return filepath.Join(r.runDir, "capture_rec", "status.json") }
func (r *Recorder) recDir() string     { return filepath.Join(r.runDir, "capture_rec") }

func (r *Recorder) pollLoop() {
	for {
		// 录制中 2 秒查一次停止条件; 空闲 10 秒看一次请求文件(dpid 常驻,
		// 不为一个很少用的功能每 2 秒醒一次)
		if r.sess.Load() != nil {
			time.Sleep(recPollEvery)
		} else {
			time.Sleep(recIdlePollEvery)
		}
		r.pollTick()
	}
}

// pollTick 一轮: 在录 → 查停止条件; 没在录 → 看请求文件(测试直接驱动)。
func (r *Recorder) pollTick() {
	if r.sess.Load() != nil {
		r.pollOnce()
		return
	}
	req := filepath.Join(r.runDir, "capture_record.request")
	stop := filepath.Join(r.runDir, "capture_record.stop")
	if _, err := os.Stat(req); err != nil {
		_ = os.Remove(stop) // 没在录也没请求: 残留的 stop 不能留给下一次录制
		return
	}
	// 先读分钟数再删(rc1 先删后读, 分钟数恒为默认 10)
	minutes := r.parseRequest()
	if _, err := os.Stat(stop); err == nil {
		_ = os.Remove(stop) // stop 与 request 同时在 → 直接取消
		return
	}
	r.start(minutes)
}

// parseRequest 读 request 文件并删之, 返回分钟数(1~30; 坏值/空 = 默认 10)。
func (r *Recorder) parseRequest() int {
	req := filepath.Join(r.runDir, "capture_record.request")
	b, err := os.ReadFile(req)
	_ = os.Remove(req)
	if err != nil {
		return recDefaultMin
	}
	var v int
	if n, _ := fmt.Sscanf(string(b), "%d", &v); n == 1 && v >= 1 && v <= recMaxMinutes {
		return v
	}
	return recDefaultMin
}

// pollOnce 一轮检查(停止文件 / 到时 / 到量); 测试直接驱动。
func (r *Recorder) pollOnce() {
	s := r.sess.Load()
	if s == nil {
		return
	}
	stop := filepath.Join(r.runDir, "capture_record.stop")
	if _, err := os.Stat(stop); err == nil {
		_ = os.Remove(stop)
		r.finishLocked()
		return
	}
	r.mu.Lock()
	expired := time.Since(r.startedAt) >= time.Duration(r.minutes)*time.Minute
	r.mu.Unlock()
	if s.bytes.Load() >= recMaxFileBytes || expired {
		r.finishLocked()
	}
}

// start 开一个录制会话(生产走 pollTick; 测试直接调)。已在录时不重开。
func (r *Recorder) start(minutes int) *recSession {
	if r.sess.Load() != nil {
		return nil
	}
	if err := os.MkdirAll(r.recDir(), 0o700); err != nil {
		return nil
	}
	name := "rec-" + time.Now().Format("20060102-150405") + ".pcap"
	path := filepath.Join(r.recDir(), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil
	}
	// pcap 全局头: magic a1b2c3d4, v2.4, snaplen 65536, LINKTYPE_RAW
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65536)
	binary.LittleEndian.PutUint32(hdr[20:24], recLinkTypeRAW)
	if _, err := f.Write(hdr[:]); err != nil {
		f.Close()
		return nil
	}
	s := &recSession{path: path, f: f, queue: make(chan recItem, recQueueLen),
		done: make(chan struct{}), finished: make(chan struct{})}
	r.mu.Lock()
	r.minutes = minutes
	r.startedAt = time.Now()
	r.sess.Store(s)
	r.mu.Unlock()
	go s.writeLoop(r)
	r.writeStatus()
	return s
}

// Stop 手工停止(测试与 stop 文件共用)。
func (r *Recorder) Stop() {
	_ = os.Remove(filepath.Join(r.runDir, "capture_record.stop"))
	r.finishLocked()
}

// finishLocked 结束当前会话并等 writeLoop 收尾(落盘 + 搬到 exports/)完成。
// 名字沿用 rc1; 不要求调用方持锁。
func (r *Recorder) finishLocked() {
	r.mu.Lock()
	s := r.sess.Swap(nil)
	r.mu.Unlock()
	if s == nil {
		return
	}
	close(s.done)
	<-s.finished
}

func (s *recSession) writeLoop(r *Recorder) {
	defer close(s.finished)
	flushStatus := time.NewTicker(recStatusEvery)
	defer flushStatus.Stop()
	broken := false // 写盘出错后不再写(会话照常等停止条件收尾)
	write := func(it recItem) {
		if broken {
			return
		}
		// 20 MB 上限在这里硬卡(pollOnce 2 秒一查只负责收尾, 不能指望它不超)
		if s.bytes.Load()+int64(16+len(it.data)) > recMaxFileBytes {
			s.bytes.Store(recMaxFileBytes)
			return
		}
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(it.ts.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(it.ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(it.data)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(len(it.data)))
		if _, err := s.f.Write(rh[:]); err != nil {
			broken = true
			return
		}
		if _, err := s.f.Write(it.data); err != nil {
			broken = true
			return
		}
		s.bytes.Add(int64(16 + len(it.data)))
	}
	for {
		select {
		case <-s.done:
			// 停止前已入队的包写完再收尾
			for {
				select {
				case it := <-s.queue:
					write(it)
					continue
				default:
				}
				break
			}
			s.finish()
			r.moveOut(s)
			r.writeStatus()
			return
		case it := <-s.queue:
			write(it)
		case <-flushStatus.C:
			r.writeStatus()
		}
	}
}

func (s *recSession) finish() {
	if s.f != nil {
		s.f.Sync()
		s.f.Close()
		s.f = nil
	}
}

// moveOut 录完把文件移到 exports/(失败留在 capture_rec/, 不算错误)。
func (r *Recorder) moveOut(s *recSession) {
	if s.path == "" {
		return
	}
	dst := filepath.Join(r.hncDir, "exports", filepath.Base(s.path))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return
	}
	_ = os.Rename(s.path, dst)
}

func (r *Recorder) writeStatus() {
	st := r.Status()
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.MkdirAll(r.recDir(), 0o700)
	tmp := r.statusFile() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, r.statusFile())
	}
}

// isRecPcapName 录制文件名(rec-YYYYMMDD-HHMMSS.pcap; httpd 导出白名单
// 同款判定)。
func isRecPcapName(n string) bool {
	// rec-YYYYMMDD-HHMMSS.pcap(总长 24)
	if len(n) != 24 || n[:4] != "rec-" || n[12] != '-' || n[19] != '.' || n[20:] != "pcap" {
		return false
	}
	for _, c := range n[4:12] + n[13:19] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
