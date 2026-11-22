package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ErrRebound is returned by Run when the capture was switched to a new
// interface via Rebind. Callers should retry Open/Run with the updated Handle.
var ErrRebound = errors.New("capture rebound to new interface")

type Options struct {
	Iface       string
	Snaplen     int
	RcvBufBytes int
}

type Stats struct {
	Packets        uint64
	KernelDrops    uint64
	DNSEvents      uint64
	TLSEvents      uint64
	FlowEvents     uint64 // rc29
	DevHintEvents  uint64 // v5.13: DHCP/DHCPv6/mDNS/SSDP/NBNS 设备识别线索
	IgnoredPackets uint64
	ParseErrors    uint64
	Panics         uint64 // recovered packet-handler panics (see Run)

	// v5.14: QUIC(HTTP/3) SNI 提取计数。进程级总数(quic.go 包级原子量),
	// 多个 Handle 读到的是同一组值。
	QUICInitial     uint64 // 识别为客户端 Initial 的包
	QUICDecryptOK   uint64
	QUICDecryptFail uint64
	QUICSNI         uint64 // IETF QUIC 产出带 SNI 的 ClientHello
	GQUICSNI        uint64 // gQUIC Q046 明文 CHLO 取到 SNI
	GQUICSkipped    uint64 // gQUIC Q050+ 加密 CHLO, 跳过

	// v5.18: 明文 HTTP Host 事件 / TCP ClientHello 截断解析与跨段重组计数。
	// TLS* 为进程级总数(tls_reasm.go 包级原子量)。
	HTTPEvents     uint64
	TLSPartial     uint64 // 截断的 ClientHello 里直接取到 SNI
	TLSPending     uint64 // 首段挂起等待末段
	TLSReassembled uint64 // 跨段重组成功
	TLSGaveUp      uint64 // 重组放弃(段不连续 / 过期 / 超限)
}

// ARPHRD_* link-layer type constants seen in the wild on Android.
// Used by Handle.linkType to dispatch the right parser in Run.
const (
	arphrdEther = 1     // wlanX, ovnetX, dummyX, ifbX, eth0
	arphrdRawIP = 519   // rmnet_dataX (Qualcomm cellular)
	arphrdNone  = 65534 // tun0 (Clash, WireGuard, Tailscale)

	epollDrainBatchMax = 64 // 单次唤醒非阻塞连读上限, 兼顾突发吞吐与控制信号响应
)

type Handle struct {
	// Placed at offset 0 for 32-bit ARM 64-bit atomic alignment.
	stats struct {
		packets  atomic.Uint64
		drops    atomic.Uint64
		dns      atomic.Uint64
		tls      atomic.Uint64
		flow     atomic.Uint64
		devHint  atomic.Uint64
		http     atomic.Uint64
		ignored  atomic.Uint64
		parseErr atomic.Uint64
		panics   atomic.Uint64
	}
	fd      int
	ifname  string
	ifindex int
	snap    int
	buf     []byte
	mu      sync.Mutex // protects fd/ifname/ifindex/linkType/rebound/epoll state
	rebound bool       // set true by Rebind, checked by Run
	// v5.12: Rebind 换下来的旧 fd 不再立即 close, 挂在这里, 由 Close() 统一关。
	retired []int

	// v5.6.0-rc3: link-layer type (ARPHRD_*) read from /sys/class/net/$iface/type.
	linkType int

	// v6.0.0: 纯事件驱动 epoll + 控制唤醒管道 (消除 500ms SO_RCVTIMEO 空闲轮询唤醒)。
	// Open 创建的实例 openedNative=true, EpollWait 使用 timeout=-1 无限阻塞(空闲期 0 次唤醒),
	// 由数据包到达、Rebind、Close 或 ctx.Done 写 wakeW 即时唤醒;
	// 单测直接字面量构造 &Handle{fd: a, ...} 时 openedNative=false, 自动懒初始化 epoll
	// 并以 100ms 兜底检查直接字段交换(100% 兼容 rawsocket_test.go)。
	epfd         int
	epollRegFD   int
	wakeR        int
	wakeW        int
	epollReady   bool
	openedNative bool
	rcvBuf       int
	closed       bool
}

// initEpollStateLocked 为 Handle 初始化 epfd 与非阻塞唤醒管道(调用方需持锁或在发布前调用)。
func (h *Handle) initEpollStateLocked() bool {
	if h.closed {
		return false
	}
	if h.epollReady {
		return h.epfd >= 0
	}
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		h.epfd, h.epollRegFD, h.wakeR, h.wakeW = -1, -1, -1, -1
		return false
	}
	var pipeFDs [2]int
	if err := syscall.Pipe2(pipeFDs[:], syscall.O_CLOEXEC|syscall.O_NONBLOCK); err != nil {
		_ = syscall.Close(epfd)
		h.epfd, h.epollRegFD, h.wakeR, h.wakeW = -1, -1, -1, -1
		return false
	}
	wakeEv := syscall.EpollEvent{
		Events: syscall.EPOLLIN,
		Fd:     int32(pipeFDs[0]),
	}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, pipeFDs[0], &wakeEv); err != nil {
		_ = syscall.Close(pipeFDs[0])
		_ = syscall.Close(pipeFDs[1])
		_ = syscall.Close(epfd)
		h.epfd, h.epollRegFD, h.wakeR, h.wakeW = -1, -1, -1, -1
		return false
	}
	h.epfd = epfd
	h.epollRegFD = -1
	h.wakeR = pipeFDs[0]
	h.wakeW = pipeFDs[1]
	h.epollReady = true
	if h.fd >= 0 {
		if err := h.syncEpollFDLocked(h.fd); err != nil {
			_ = syscall.Close(pipeFDs[0])
			_ = syscall.Close(pipeFDs[1])
			_ = syscall.Close(epfd)
			h.epfd, h.epollRegFD, h.wakeR, h.wakeW = -1, -1, -1, -1
			h.epollReady = false
			return false
		}
	}
	return true
}

func (h *Handle) syncEpollFDLocked(fd int) error {
	if !h.epollReady || h.epfd < 0 || fd < 0 {
		return syscall.EBADF
	}
	if h.epollRegFD == fd {
		return nil
	}
	if h.epollRegFD >= 0 {
		_ = syscall.EpollCtl(h.epfd, syscall.EPOLL_CTL_DEL, h.epollRegFD, nil)
		h.epollRegFD = -1
	}
	ev := syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR | syscall.EPOLLHUP,
		Fd:     int32(fd),
	}
	if err := syscall.EpollCtl(h.epfd, syscall.EPOLL_CTL_ADD, fd, &ev); err != nil {
		return err
	}
	h.epollRegFD = fd
	return nil
}

func (h *Handle) pokeWakeLocked() {
	if h.epollReady && h.wakeW >= 0 {
		var one [1]byte
		one[0] = 1
		_, _ = syscall.Write(h.wakeW, one[:])
	}
}

func (h *Handle) pokeWake() {
	h.mu.Lock()
	h.pokeWakeLocked()
	h.mu.Unlock()
}

func drainWakeFD(wakeR int) {
	if wakeR < 0 {
		return
	}
	var scratch [32]byte
	for {
		n, err := syscall.Read(wakeR, scratch[:])
		if n <= 0 || err != nil {
			return
		}
	}
}

// Open creates a raw AF_PACKET socket, attaches cBPF, and binds to iface.
func Open(opts Options) (*Handle, error) {
	if opts.Iface == "" {
		return nil, fmt.Errorf("no iface")
	}
	if opts.Snaplen <= 0 {
		opts.Snaplen = 1024
	}

	ifc, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("lookup iface %s: %w", opts.Iface, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket AF_PACKET: %w", err)
	}

	closeFD := func(reason string, e error) error {
		_ = syscall.Close(fd)
		return fmt.Errorf("%s: %w", reason, e)
	}

	if opts.RcvBufBytes > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, opts.RcvBufBytes)
	}

	// Attach filter before bind so unfiltered packets do not queue on the socket.
	lt, _ := readLinkType(opts.Iface)
	var raw []syscall.SockFilter
	switch lt {
	case arphrdRawIP, arphrdNone:
		raw, err = BuildFilterRawIP(uint32(opts.Snaplen))
	default:
		raw, err = BuildFilter(uint32(opts.Snaplen))
	}
	if err != nil {
		return nil, closeFD("build bpf", err)
	}
	if err := AttachFilter(fd, raw); err != nil {
		return nil, closeFD("attach bpf", err)
	}

	sa := &syscall.SockaddrLinklayer{Protocol: htons(ETH_P_ALL), Ifindex: ifc.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, closeFD("bind "+opts.Iface, err)
	}

	// Best-effort drain of anything queued during setup.
	drainBuf := make([]byte, 64)
	for i := 0; i < 1024; i++ {
		_, _, e := syscall.Recvfrom(fd, drainBuf, syscall.MSG_DONTWAIT)
		if e != nil {
			break
		}
	}

	h := &Handle{
		fd:           fd,
		ifname:       opts.Iface,
		ifindex:      ifc.Index,
		snap:         opts.Snaplen,
		buf:          make([]byte, max(opts.Snaplen, quicSnaplen, tlsSnaplen)+64),
		linkType:     lt,
		epfd:         -1,
		epollRegFD:   -1,
		wakeR:        -1,
		wakeW:        -1,
		openedNative: true,
		rcvBuf:       opts.RcvBufBytes,
	}
	if !h.initEpollStateLocked() {
		// 极端裁剪环境若不支持 epoll, 回退阻塞超时模式确保抓包可用。
		_ = syscall.SetNonblock(fd, false)
		tv := syscall.Timeval{Sec: 0, Usec: 500_000}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	}
	return h, nil
}

// readLinkType returns the ARPHRD_* value from /sys/class/net/$iface/type.
// 0 on any failure (callers treat 0 as "assume Ethernet" for safety).
func readLinkType(iface string) (int, error) {
	if strings.ContainsAny(iface, "/\\..") {
		return 0, fmt.Errorf("invalid iface name: %s", iface)
	}
	data, err := os.ReadFile("/sys/class/net/" + iface + "/type")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// LinkType returns the ARPHRD_* link type discovered at Open time.
// Used by self_capture.go for diagnostic logging.
func (h *Handle) LinkType() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.linkType
}

// CurrentIfindex returns the ifindex the handle was opened (or last rebound) with.
func (h *Handle) CurrentIfindex() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ifindex
}

// Rebind switches the capture to a different network interface. It creates
// a new raw socket, attaches the appropriate BPF filter, atomically swaps the
// fd, and immediately wakes EpollWait via wakeW so Run returns ErrRebound in 0ms.
func (h *Handle) Rebind(newIface string) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return fmt.Errorf("rebind on closed handle")
	}
	snap := h.snap
	rcvBuf := h.rcvBuf
	h.mu.Unlock()

	ifc, err := net.InterfaceByName(newIface)
	if err != nil {
		return fmt.Errorf("rebind lookup %s: %w", newIface, err)
	}

	lt, _ := readLinkType(newIface)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, int(htons(ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("rebind socket: %w", err)
	}

	if rcvBuf > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBuf)
	}

	var raw []syscall.SockFilter
	switch lt {
	case arphrdRawIP, arphrdNone:
		raw, err = BuildFilterRawIP(uint32(snap))
	default:
		raw, err = BuildFilter(uint32(snap))
	}
	if err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("rebind build bpf: %w", err)
	}
	if err := AttachFilter(fd, raw); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("rebind attach bpf: %w", err)
	}

	sa := &syscall.SockaddrLinklayer{Protocol: htons(ETH_P_ALL), Ifindex: ifc.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("rebind bind %s: %w", newIface, err)
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = syscall.Close(fd)
		return fmt.Errorf("rebind on closed handle")
	}
	oldFD := h.fd
	h.fd = fd
	h.ifname = newIface
	h.ifindex = ifc.Index
	h.linkType = lt
	h.rebound = true
	if oldFD >= 0 {
		h.retired = append(h.retired, oldFD)
	}
	if !h.epollReady || h.epfd < 0 || h.syncEpollFDLocked(fd) != nil {
		_ = syscall.SetNonblock(fd, false)
		tv := syscall.Timeval{Sec: 0, Usec: 500_000}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	}
	h.pokeWakeLocked()
	h.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[dpid/capture] rebind: switched to %s (ifindex=%d, linktype=%d)\n", newIface, ifc.Index, lt)
	return nil
}

func (h *Handle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	h.pokeWakeLocked()
	if h.fd >= 0 {
		_ = syscall.Close(h.fd)
		h.fd = -1
	}
	for _, fd := range h.retired {
		_ = syscall.Close(fd)
	}
	h.retired = nil
	if h.epollReady {
		if h.epfd >= 0 {
			_ = syscall.Close(h.epfd)
			h.epfd = -1
		}
		if h.wakeR >= 0 {
			_ = syscall.Close(h.wakeR)
			h.wakeR = -1
		}
		if h.wakeW >= 0 {
			_ = syscall.Close(h.wakeW)
			h.wakeW = -1
		}
		h.epollRegFD = -1
		h.epollReady = false
	}
}

func (h *Handle) Iface() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ifname
}

func (h *Handle) Stats() Stats {
	h.refreshDrops()
	return Stats{
		Packets:        h.stats.packets.Load(),
		KernelDrops:    h.stats.drops.Load(),
		DNSEvents:      h.stats.dns.Load(),
		TLSEvents:      h.stats.tls.Load(),
		FlowEvents:     h.stats.flow.Load(),
		DevHintEvents:  h.stats.devHint.Load(),
		IgnoredPackets: h.stats.ignored.Load(),
		ParseErrors:    h.stats.parseErr.Load(),
		Panics:         h.stats.panics.Load(),

		QUICInitial:     quicStats.initial.Load(),
		QUICDecryptOK:   quicStats.decryptOK.Load(),
		QUICDecryptFail: quicStats.decryptFail.Load(),
		QUICSNI:         quicStats.sni.Load(),
		GQUICSNI:        quicStats.gquicSNI.Load(),
		GQUICSkipped:    quicStats.gquicSkipped.Load(),

		HTTPEvents:     h.stats.http.Load(),
		TLSPartial:     tlsStats.partial.Load(),
		TLSPending:     tlsStats.pending.Load(),
		TLSReassembled: tlsStats.reassembled.Load(),
		TLSGaveUp:      tlsStats.gaveUp.Load(),
	}
}

// tpacketStats matches struct tpacket_stats in <linux/if_packet.h>.
// PACKET_STATISTICS returns deltas since the last call and resets them.
type tpacketStats struct {
	Packets uint32
	Drops   uint32
}

func (h *Handle) refreshDrops() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd < 0 {
		return
	}
	var st tpacketStats
	sz := uint32(unsafe.Sizeof(st))
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(h.fd),
		uintptr(syscall.SOL_PACKET),
		uintptr(syscall.PACKET_STATISTICS),
		uintptr(unsafe.Pointer(&st)),
		uintptr(unsafe.Pointer(&sz)),
		0,
	)
	if e != 0 {
		return
	}
	h.stats.drops.Add(uint64(st.Drops))
}

func (h *Handle) dispatchCapturedPacket(pktLen int, linkType int, onEvent func(Event)) {
	h.stats.packets.Add(1)
	defer func() {
		if r := recover(); r != nil {
			c := h.stats.panics.Add(1)
			if c == 1 || c%1000 == 0 {
				fmt.Fprintf(os.Stderr, "[dpid/capture] recovered from packet handler panic #%d: %v\n", c, r)
			}
		}
	}()
	var ev Event
	var res ParseResult
	switch linkType {
	case arphrdRawIP, arphrdNone:
		ev, res = parseRawIPPacket(h.buf[:pktLen], time.Now())
	default:
		ev, res = parsePacket(h.buf[:pktLen], time.Now())
	}
	ethLink := linkType != arphrdRawIP && linkType != arphrdNone
	if rec := DefaultRecorder.Load(); rec != nil {
		rec.(*Recorder).Offer(ethLink, h.buf[:pktLen], ev)
	}
	switch res {
	case ParseOK:
		switch ev.Kind {
		case EventDNS:
			h.stats.dns.Add(1)
		case EventTLSClientHello:
			h.stats.tls.Add(1)
		case EventFlow:
			h.stats.flow.Add(1)
		case EventDevHint:
			h.stats.devHint.Add(1)
		case EventHTTP:
			h.stats.http.Add(1)
		}
		onEvent(ev)
	case ParseIgnore:
		h.stats.ignored.Add(1)
	case ParseMalformed:
		h.stats.parseErr.Add(1)
	}
}

// Run reads packets until ctx is cancelled using pure event-driven Linux epoll.
// onEvent runs on the capture goroutine; it must not block on I/O.
func (h *Handle) Run(ctx context.Context, onEvent func(Event)) error {
	h.mu.Lock()
	useEpoll := h.initEpollStateLocked()
	nativeInfiniteWait := h.openedNative
	h.mu.Unlock()

	if useEpoll {
		stopWatch := make(chan struct{})
		defer close(stopWatch)
		go func() {
			select {
			case <-ctx.Done():
				h.pokeWake()
			case <-stopWatch:
			}
		}()
		return h.runEpollLoop(ctx, nativeInfiniteWait, onEvent)
	}
	return h.runRecvfromFallback(ctx, onEvent)
}

func (h *Handle) checkSocketError(fd int) (err error, retry bool) {
	soErr, gerr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if gerr == nil && soErr != 0 {
		e := syscall.Errno(soErr)
		if e == syscall.ENOBUFS {
			h.stats.drops.Add(1)
			return nil, true
		}
		return fmt.Errorf("socket error: %w", e), false
	}
	return fmt.Errorf("socket hangup: %w", syscall.ENETDOWN), false
}

func (h *Handle) runEpollLoop(ctx context.Context, infiniteWait bool, onEvent func(Event)) error {
	var events [4]syscall.EpollEvent
	waitMs := -1
	if !infiniteWait {
		// 单测直接构造 &Handle{fd: a} 并在锁内直接改写 h.fd 而不调用 Rebind 时,
		// 使用 100ms 周期校验确保 TestRun_ReturnsErrReboundAfterSwap 毫秒级返回。
		waitMs = 100
	}

	for {
		if ctx.Err() != nil {
			return nil
		}

		h.mu.Lock()
		if h.rebound {
			h.mu.Unlock()
			return ErrRebound
		}
		if h.closed || h.fd < 0 {
			h.mu.Unlock()
			return nil
		}
		fd := h.fd
		epfd := h.epfd
		wakeR := h.wakeR
		linkType := h.linkType
		var syncErr error
		if epfd >= 0 {
			syncErr = h.syncEpollFDLocked(fd)
		}
		if epfd < 0 || syncErr != nil {
			_ = syscall.SetNonblock(fd, false)
			tv := syscall.Timeval{Sec: 0, Usec: 500_000}
			_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
			h.mu.Unlock()
			return h.runRecvfromFallback(ctx, onEvent)
		}
		h.mu.Unlock()

		nev, werr := syscall.EpollWait(epfd, events[:], waitMs)
		h.mu.Lock()
		swapped := h.rebound
		closedNow := h.closed || h.fd < 0
		h.mu.Unlock()
		if swapped {
			return ErrRebound
		}
		if closedNow || ctx.Err() != nil {
			return nil
		}
		if werr != nil {
			if errors.Is(werr, syscall.EINTR) || errors.Is(werr, syscall.EAGAIN) {
				continue
			}
			if errors.Is(werr, syscall.EBADF) {
				h.mu.Lock()
				wasRebound := h.rebound
				h.mu.Unlock()
				if wasRebound {
					return ErrRebound
				}
				return nil
			}
			return fmt.Errorf("epoll_wait: %w", werr)
		}
		if nev <= 0 {
			continue
		}

		pktReady := false
		pktErr := false
		for i := 0; i < nev; i++ {
			evFD := int(events[i].Fd)
			if evFD == wakeR {
				drainWakeFD(wakeR)
			} else if evFD == fd {
				if events[i].Events&(syscall.EPOLLERR|syscall.EPOLLHUP) != 0 {
					pktErr = true
				}
				if events[i].Events&syscall.EPOLLIN != 0 {
					pktReady = true
				}
			}
		}
		if pktErr && !pktReady {
			err, retry := h.checkSocketError(fd)
			if retry {
				continue
			}
			return err
		}
		if !pktReady {
			continue
		}

		received := 0
		for batch := 0; batch < epollDrainBatchMax; batch++ {
			if ctx.Err() != nil {
				return nil
			}
			n, _, err := syscall.Recvfrom(fd, h.buf, syscall.MSG_DONTWAIT)
			h.mu.Lock()
			swappedNow := h.rebound
			h.mu.Unlock()
			if swappedNow {
				return ErrRebound
			}
			if err != nil {
				switch err {
				case syscall.ENOBUFS:
					h.stats.drops.Add(1)
					continue
				case syscall.EAGAIN, syscall.EINTR:
					batch = epollDrainBatchMax
					continue
				case syscall.EBADF:
					h.mu.Lock()
					wasRebound := h.rebound
					h.mu.Unlock()
					if wasRebound {
						return ErrRebound
					}
					return nil
				default:
					return fmt.Errorf("recvfrom: %w", err)
				}
			}
			if n <= 0 {
				break
			}
			received++
			h.dispatchCapturedPacket(n, linkType, onEvent)
		}
		if pktErr && received == 0 {
			err, retry := h.checkSocketError(fd)
			if !retry {
				return err
			}
		}
	}
}

func (h *Handle) runRecvfromFallback(ctx context.Context, onEvent func(Event)) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		h.mu.Lock()
		if h.rebound {
			h.mu.Unlock()
			return ErrRebound
		}
		if h.closed || h.fd < 0 {
			h.mu.Unlock()
			return nil
		}
		fd := h.fd
		linkType := h.linkType
		h.mu.Unlock()

		n, _, err := syscall.Recvfrom(fd, h.buf, 0)
		h.mu.Lock()
		swapped := h.rebound
		h.mu.Unlock()
		if swapped {
			return ErrRebound
		}
		if err != nil {
			switch err {
			case syscall.ENOBUFS:
				h.stats.drops.Add(1)
				continue
			case syscall.EAGAIN, syscall.EINTR:
				continue
			case syscall.EBADF:
				h.mu.Lock()
				wasRebound := h.rebound
				h.mu.Unlock()
				if wasRebound {
					return ErrRebound
				}
				return nil
			default:
				return fmt.Errorf("recvfrom: %w", err)
			}
		}
		if n <= 0 {
			continue
		}
		h.dispatchCapturedPacket(n, linkType, onEvent)
	}
}
