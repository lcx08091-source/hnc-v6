package probe

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"syscall"

	"hnc.io/dpid/capture"
)

type Result struct {
	Timestamp         int64                    `json:"timestamp"`
	Kernel            string                   `json:"kernel"`
	AFPacketAvailable bool                     `json:"af_packet_available"`
	AFPacketError     string                   `json:"af_packet_error,omitempty"`
	APIface           string                   `json:"ap_iface"`
	APIfaceSource     string                   `json:"ap_iface_source"`
	APIfaceCandidates []capture.IfaceCandidate `json:"ap_iface_candidates"`
	ConntrackReadable bool                     `json:"conntrack_readable"`
	ConntrackPath     string                   `json:"conntrack_path,omitempty"`
	OffloadHint       bool                     `json:"offload_hint"`
	OffloadEvidence   []string                 `json:"offload_evidence,omitempty"`
	NetdLogReadable   bool                     `json:"netd_log_readable"`
	TLSReassembly     bool                     `json:"tls_reassembly"`
	IPv6Capture       bool                     `json:"ipv6_capture"`
}

type Options struct {
	IfaceOverride string
}

func Run(opt Options) Result {
	r := Result{
		Timestamp:     time.Now().Unix(),
		Kernel:        readKernel(),
		TLSReassembly: false,
	}

	// BUG-013: 真实 IPv6 捕获探测(不再硬编码 false)
	// 先做系统级探测,后面 AP iface 确定后再做接口级确认
	r.IPv6Capture = detectIPv6Capture()

	if err := probeAFPacket(); err == nil {
		r.AFPacketAvailable = true
	} else {
		r.AFPacketError = err.Error()
	}

	cands, _ := capture.DiscoverAPCandidates()
	r.APIfaceCandidates = cands
	switch {
	case opt.IfaceOverride != "":
		r.APIface = opt.IfaceOverride
		r.APIfaceSource = "config"
	case len(cands) > 0:
		r.APIface = cands[0].Name
		r.APIfaceSource = "auto"
	}

	// BUG-013: 如果 AP iface 已确定,用接口级探测覆盖系统级结果
	if r.APIface != "" {
		r.IPv6Capture = detectIPv6OnIface(r.APIface)
	}

	for _, p := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
		if f, err := os.Open(p); err == nil {
			_ = f.Close()
			r.ConntrackReadable = true
			r.ConntrackPath = p
			break
		}
	}

	if ev := detectOffloadHints(); len(ev) > 0 {
		r.OffloadHint = true
		r.OffloadEvidence = ev
	}

	for _, p := range []string{
		"/data/misc/dhcp/dnsmasq.leases",
		"/data/vendor/wifi/hostapd/hostapd.conf",
	} {
		if _, err := os.Stat(p); err == nil {
			r.NetdLogReadable = true
			break
		}
	}

	return r
}

func probeAFPacket() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	_ = syscall.Close(fd)
	return nil
}

func readKernel() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	n := 0
	for n < len(u.Release) && u.Release[n] != 0 {
		n++
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(u.Release[i])
	}
	return string(b)
}

// detectOffloadHints is a static hint only. It must not change mode in rc1.2.
func detectOffloadHints() []string {
	var ev []string
	for _, p := range []string{
		"/sys/fs/bpf/tethering",
		"/sys/fs/bpf/net_shared/prog_offload_schedcls_tether_upstream4_ether",
		"/sys/fs/bpf/net_shared/prog_offload_schedcls_tether_downstream4_ether",
		"/sys/kernel/debug/ipa",
		"/proc/hnat",
	} {
		if _, err := os.Stat(p); err == nil {
			ev = append(ev, filepath.Base(p))
		}
	}
	return ev
}

// detectIPv6Capture checks if the system has active IPv6 connections.
// Reads /proc/net/tcp6 — if there are entries beyond the header line,
// IPv6 networking is active and BPF capture can process IPv6 traffic.
func detectIPv6Capture() bool {
	f, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // skip header
		}
		// Any non-header line means there's an IPv6 TCP entry
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			return true
		}
	}
	return false
}

// detectIPv6OnIface checks if a specific network interface has IPv6 addresses.
// Reads /proc/net/if_inet6 which lists per-interface IPv6 addresses.
// Format: "<hex_addr> <ifindex> <prefix_len> <scope> <flags> <iface_name>"
func detectIPv6OnIface(iface string) bool {
	if iface == "" {
		return false
	}
	f, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		// File doesn't exist → no IPv6 at all
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 && fields[5] == iface {
			return true
		}
	}
	return false
}

func WriteJSON(path string, r Result) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b, 0o644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
