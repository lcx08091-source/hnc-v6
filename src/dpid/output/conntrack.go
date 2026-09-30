// Package output - conntrack.go: read /proc/net/nf_conntrack and count flows.
//
// Android caveat: many Android kernels disable the conntrack export (or
// gate it behind a SELinux denial); we treat any open/read error as
// "not readable" and simply report ConntrackFlows=0 with ConntrackReadable=false.
// This is the rc28.1.1 contract that WebUI already understands.

package output

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// ConntrackPaths is the canonical lookup order. On modern kernels only the
// first exists.
var ConntrackPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack",
}

type ConntrackReport struct {
	Available bool   // file exists
	Readable  bool   // we could open + scan it
	Path      string // which path we used
	Flows     int    // number of conntrack entries
}

// ReadConntrack scans the first available conntrack export and returns
// the entry count. Counting is line-based; we cap at maxConntrackLines to
// avoid pathological behaviour on huge tables.
func ReadConntrack() ConntrackReport {
	return ReadConntrackWith(nil)
}

// ReadConntrackWith 同 ReadConntrack, onDst 非 nil 时对每条记录的原方向
// 目的地址(第一个 "dst=" 字段, 即客户端连向的远端)回调一次(v5.18: 供
// IP→域名表给活跃连接顺延映射)。地址已按 net.IP.String() 规范化。
func ReadConntrackWith(onDst func(dst string)) ConntrackReport {
	const maxConntrackLines = 1 << 16 // 65536 flows ought to be enough

	var r ConntrackReport
	for _, p := range ConntrackPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		// File exists; available=true regardless of whether we can read it.
		r.Available = true
		r.Path = p

		f, err := os.Open(p)
		if err != nil {
			// Most likely SELinux EACCES.
			return r
		}
		// Conntrack lines can be long (IPv6 + extensions). Use a generous
		// buffer rather than the default 64KB scanner cap which is fine but
		// we still set it explicitly to be safe.
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4096), 1024*1024)
		count := 0
		for sc.Scan() {
			// One conntrack entry per line; skip blank or comment lines.
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			if line[0] == '#' {
				continue
			}
			count++
			if onDst != nil {
				if d := conntrackOrigDst(line); d != "" {
					onDst(d)
				}
			}
			if count >= maxConntrackLines {
				break
			}
		}
		_ = f.Close()

		if err := sc.Err(); err != nil {
			// Partial read still counts as readable.
			r.Readable = count > 0
			r.Flows = count
			return r
		}
		r.Readable = true
		r.Flows = count
		return r
	}
	return r
}

// conntrackOrigDst 取一行 conntrack 记录里第一个 dst= 的值(原方向目的地址),
// 规范化成 net.IP.String()。解析不出返回 ""。
func conntrackOrigDst(line string) string {
	i := strings.Index(line, " dst=")
	if i < 0 {
		return ""
	}
	v := line[i+len(" dst="):]
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// parseConntrackLine is kept for future expansion: rc30 may want to bin
// flows by proto/state to refine background detection. Today we only
// count lines.
//
// Format examples (kernel 5.x):
//
//	ipv4     2 tcp      6 431999 ESTABLISHED src=... dst=... ...
//	ipv6     10 udp     17 29 src=... dst=... ...
func parseConntrackLine(line string) (proto, state string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", "", false
	}
	// fields[2] is proto name; state is field with no '=' near the front of
	// the post-numeric segment.
	proto = fields[2]
	for _, f := range fields[3:] {
		if strings.Contains(f, "=") {
			break
		}
		if f == "ASSURED" || f == "UNREPLIED" || f == "SEEN_REPLY" {
			continue
		}
		state = f
		break
	}
	return proto, state, true
}
