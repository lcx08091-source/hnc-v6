package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		IPv6Capture:   false,
	}

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
