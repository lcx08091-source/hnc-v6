package capture

import (
	"context"
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
	IgnoredPackets uint64
	ParseErrors    uint64
}

// ARPHRD_* link-layer type constants seen in the wild on Android.
// Used by Handle.linkType to dispatch the right parser in Run.
const (
	arphrdEther = 1     // wlanX, ovnetX, dummyX, ifbX, eth0
	arphrdRawIP = 519   // rmnet_dataX (Qualcomm cellular)
	arphrdNone  = 65534 // tun0 (Clash, WireGuard, Tailscale)
)

type Handle struct {
	fd        int
	iface     string
	snap      int
	buf       []byte
	closeOnce sync.Once

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
		ignored  atomic.Uint64
		parseErr atomic.Uint64
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
	lt := readLinkType(opts.Iface)
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
		fd:       fd,
		iface:    opts.Iface,
		snap:     opts.Snaplen,
		buf:      make([]byte, opts.Snaplen+64),
		linkType: lt,
	}, nil
}

// readLinkType returns the ARPHRD_* value from /sys/class/net/$iface/type.
// 0 on any failure (callers treat 0 as "assume Ethernet" for safety).
func readLinkType(iface string) int {
	data, err := os.ReadFile("/sys/class/net/" + iface + "/type")
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return n
}

// LinkType returns the ARPHRD_* link type discovered at Open time.
// Used by self_capture.go for diagnostic logging.
func (h *Handle) LinkType() int { return h.linkType }

func (h *Handle) Close() {
	h.closeOnce.Do(func() {
		if h.fd >= 0 {
			_ = syscall.Close(h.fd)
			h.fd = -1
		}
	})
}

func (h *Handle) Iface() string { return h.iface }

func (h *Handle) Stats() Stats {
	h.refreshDrops()
	return Stats{
		Packets:        h.stats.packets.Load(),
		KernelDrops:    h.stats.drops.Load(),
		DNSEvents:      h.stats.dns.Load(),
		TLSEvents:      h.stats.tls.Load(),
		FlowEvents:     h.stats.flow.Load(),
		IgnoredPackets: h.stats.ignored.Load(),
		ParseErrors:    h.stats.parseErr.Load(),
	}
}

// tpacketStats matches struct tpacket_stats in <linux/if_packet.h>.
// PACKET_STATISTICS returns deltas since the last call and resets them.
type tpacketStats struct {
	Packets uint32
	Drops   uint32
}

func (h *Handle) refreshDrops() {
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

		n, _, err := syscall.Recvfrom(h.fd, h.buf, 0)
		if err != nil {
			switch err {
			case syscall.EAGAIN, syscall.EINTR:
				continue
			case syscall.EBADF:
				return nil
			default:
				return fmt.Errorf("recvfrom: %w", err)
			}
		}
		if n <= 0 {
			continue
		}

		h.stats.packets.Add(1)
		// v5.6.0-rc3: dispatch parser by link layer. ARPHRD_RAWIP (519)
		// on Qualcomm cellular and ARPHRD_NONE (65534) on tun VPN both
		// deliver bare IP packets — using the Ethernet parser would read
		// IP header bytes as bogus etherType and silently drop everything.
		var ev Event
		var res ParseResult
		switch h.linkType {
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
			}
			onEvent(ev)
		case ParseIgnore:
			h.stats.ignored.Add(1)
		case ParseMalformed:
			h.stats.parseErr.Add(1)
		}
	}
}
