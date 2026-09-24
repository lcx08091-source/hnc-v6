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
	"time"
	"unsafe"

	"syscall"
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
}

// ARPHRD_* link-layer type constants seen in the wild on Android.
// Used by Handle.linkType to dispatch the right parser in Run.
const (
	arphrdEther = 1     // wlanX, ovnetX, dummyX, ifbX, eth0
	arphrdRawIP = 519   // rmnet_dataX (Qualcomm cellular)
	arphrdNone  = 65534 // tun0 (Clash, WireGuard, Tailscale)
)

type Handle struct {
	fd      int
	ifname  string
	ifindex int
	snap    int
	buf     []byte
	mu      sync.Mutex // protects fd/ifname/ifindex/linkType/rebound during Rebind
	rebound bool       // set true by Rebind, checked by Run after EBADF
	// v5.12: Rebind 换下来的旧 fd 不再立即 close, 挂在这里, 由 Close() 统一关。
	// 旧实现在 Run 从 h.fd 取出旧 fd、尚未进入 recvfrom 的窗口里就 close 了它,
	// fd 号可能立刻被本进程别处(状态文件 flush / 读 /proc 等)复用 → Run 对
	// 一个无关 fd 调 recvfrom: 普通文件得 ENOTSOCK → 被当成致命错误, 整个
	// capture 退出进入 blind 模式且不再重试; 若复用成了别的 socket 还会偷读数据。
	retired []int

	// v5.6.0-rc3: link-layer type (ARPHRD_*) read from
	// /sys/class/net/$iface/type at Open. Determines whether parsePacket
	// (Ethernet, 14-byte L2 header) or parseRawIPPacket (no L2 header)
	// is dispatched in Run. Values seen on Android in the wild:
	//   1     = ARPHRD_ETHER   (wlanX AP-side, wlan0 STA, ovnetX)
	//   519   = ARPHRD_RAWIP   (Qualcomm rmnet cellular)
	//   65534 = ARPHRD_NONE    (tun used by VPN: Clash, WG, Tailscale)
	linkType int

	stats struct {
		packets  atomic.Uint64
		drops    atomic.Uint64
		dns      atomic.Uint64
		tls      atomic.Uint64
		flow     atomic.Uint64
		devHint  atomic.Uint64
		ignored  atomic.Uint64
		parseErr atomic.Uint64
		panics   atomic.Uint64
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

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
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

	// 500ms timeout allows cooperative shutdown through ctx.
	tv := syscall.Timeval{Sec: 0, Usec: 500_000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, closeFD("set SO_RCVTIMEO", err)
	}

	// Attach filter before bind so unfiltered packets do not queue on the socket.
	//
	// v5.6.0-rc4: choose filter by link layer. RawIP (rmnet, 519) and
	// tun (NONE, 65534) have no Ethernet header — using the Ether-aware
	// BuildFilter on these would reject all packets in the kernel BPF
	// program, leaving recvfrom() permanently silent (the exact bug
	// observed in rc1-rc3).
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

	// v5.6.0-rc3: detect link type so Run can dispatch to the right
	// parser. Read failure or unknown type → default to Ethernet (the
	// historical behavior; main AP capture always opens on Ether-class
	// wlanX so this preserves bug-for-bug compat).
	// (v5.6.0-rc4: `lt` was already read above for filter selection.)

	return &Handle{
		fd:      fd,
		ifname:  opts.Iface,
		ifindex: ifc.Index,
		snap:    opts.Snaplen,
		// v5.14: BPF 对 QUIC 分支返回 max(snaplen, quicSnaplen), 缓冲按大者
		// 分配, 否则 1200+ 字节的 Initial 被 recvfrom 截断、GCM 必然失败。
		buf:      make([]byte, max(opts.Snaplen, quicSnaplen)+64),
		linkType: lt,
	}, nil
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
// a new raw socket, attaches the appropriate BPF filter, and atomically
// swaps the fd so the Run goroutine picks up the new socket on its next
// recvfrom call (the old fd is closed, causing EBADF → clean exit from Run).
func (h *Handle) Rebind(newIface string) error {
	ifc, err := net.InterfaceByName(newIface)
	if err != nil {
		return fmt.Errorf("rebind lookup %s: %w", newIface, err)
	}

	lt, _ := readLinkType(newIface)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("rebind socket: %w", err)
	}

	// 500ms timeout matches Open().
	tv := syscall.Timeval{Sec: 0, Usec: 500_000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("rebind set SO_RCVTIMEO: %w", err)
	}

	var raw []syscall.SockFilter
	switch lt {
	case arphrdRawIP, arphrdNone:
		raw, err = BuildFilterRawIP(uint32(h.snap))
	default:
		raw, err = BuildFilter(uint32(h.snap))
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

	// Atomic swap: Run() reads fd under lock, so it will see the new fd.
	// v5.12: 旧 fd 不在这里 close(见 retired 字段注释)。Run 的 recvfrom 最多
	// 500ms(SO_RCVTIMEO)后返回, 发现 h.fd 已换即返回 ErrRebound; 旧 fd 由
	// 调用方随后的 Close() 关闭。
	h.mu.Lock()
	oldFD := h.fd
	h.fd = fd
	h.ifname = newIface
	h.ifindex = ifc.Index
	h.linkType = lt
	h.rebound = true
	if oldFD >= 0 {
		h.retired = append(h.retired, oldFD)
	}
	h.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[dpid/capture] rebind: switched to %s (ifindex=%d, linktype=%d)\n", newIface, ifc.Index, lt)
	return nil
}

func (h *Handle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd >= 0 {
		_ = syscall.Close(h.fd)
		h.fd = -1
	}
	for _, fd := range h.retired { // v5.12
		_ = syscall.Close(fd)
	}
	h.retired = nil
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
	}
}

// tpacketStats matches struct tpacket_stats in <linux/if_packet.h>.
// PACKET_STATISTICS returns deltas since the last call and resets them.
type tpacketStats struct {
	Packets uint32
	Drops   uint32
}

func (h *Handle) refreshDrops() {
	// v5.12: 持锁读 fd 并在锁内完成 getsockopt —— 旧代码无锁读 h.fd, 与
	// Rebind/Close 构成数据竞争, 可能对已关闭(甚至被复用)的 fd 号取统计。
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

// Run reads packets until ctx is cancelled. onEvent runs on the capture goroutine;
// it must not block on I/O.
func (h *Handle) Run(ctx context.Context, onEvent func(Event)) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		h.mu.Lock()
		fd := h.fd
		linkType := h.linkType // v5.12: 与 fd 一起在锁内取, 旧代码无锁读(数据竞争)
		h.mu.Unlock()
		if fd < 0 {
			return nil // Close() was called
		}

		n, _, err := syscall.Recvfrom(fd, h.buf, 0)
		// v5.12: recvfrom 返回后先看 fd 是否已被 Rebind 换掉, 是则按设计返回
		// ErrRebound(旧实现依赖旧 fd 被 close 产生 EBADF, 但阻塞中的 recvfrom
		// 不会因 close 被唤醒, 且 close 后的 fd 号复用会导致 ENOTSOCK 致命退出)。
		h.mu.Lock()
		swapped := h.fd != fd && h.rebound
		h.mu.Unlock()
		if swapped {
			return ErrRebound
		}
		if err != nil {
			switch err {
			case syscall.EAGAIN, syscall.EINTR:
				continue
			case syscall.EBADF:
				// fd was closed — check if it was a rebind or a clean shutdown
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

		h.stats.packets.Add(1)
		// A single malformed or hostile packet must never take down the capture
		// goroutine (and with it the whole dpid process). Wrap parse + onEvent in
		// a recover: count the panic, log it (rate-limited so a panic-triggering
		// flood can't spam logs), and keep reading the next packet.
		func() {
			defer func() {
				if r := recover(); r != nil {
					c := h.stats.panics.Add(1)
					if c == 1 || c%1000 == 0 {
						fmt.Fprintf(os.Stderr, "[dpid/capture] recovered from packet handler panic #%d: %v\n", c, r)
					}
				}
			}()
			// v5.6.0-rc3: dispatch parser by link layer. ARPHRD_RAWIP (519)
			// on Qualcomm cellular and ARPHRD_NONE (65534) on tun VPN both
			// deliver bare IP packets — using the Ethernet parser would read
			// IP header bytes as bogus etherType and silently drop everything.
			var ev Event
			var res ParseResult
			switch linkType {
			case arphrdRawIP, arphrdNone:
				ev, res = parseRawIPPacket(h.buf[:n], time.Now())
			default:
				// 0 (unknown — fallback), 1 (Ether), or anything else uses
				// the original Ethernet path. wlan2 = AP mode, wlan0 = STA,
				// ovnetX = bridged Ether-class all land here.
				ev, res = parsePacket(h.buf[:n], time.Now())
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
				}
				onEvent(ev)
			case ParseIgnore:
				h.stats.ignored.Add(1)
			case ParseMalformed:
				h.stats.parseErr.Add(1)
			}
		}()
	}
}
