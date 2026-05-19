package capture

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const hncHotspotIfaceFile = "/data/local/hnc/run/hotspot_iface"

// Interfaces in this list are never selected unless explicitly provided by HNC hint/config.
var excludedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^lo$`),
	regexp.MustCompile(`^dummy\d*$`),
	regexp.MustCompile(`^ifb\d*$`),
	regexp.MustCompile(`^tun\d*$`),
	regexp.MustCompile(`^vpn\d*$`),
	regexp.MustCompile(`^rmnet.*$`),
	regexp.MustCompile(`^ccmni\d*$`),
	regexp.MustCompile(`^wwan\d*$`),
	regexp.MustCompile(`^wlan0$`), // usually STA/upstream Wi-Fi, not hotspot AP
}

var apNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^ap\d*$`),
	regexp.MustCompile(`^softap\d*$`),
	regexp.MustCompile(`^swlan\d+$`),
	regexp.MustCompile(`^wlan[1-9]\d*$`),
}

type IfaceCandidate struct {
	Name       string `json:"name"`
	Index      int    `json:"index"`
	IPv4       string `json:"ipv4,omitempty"`
	HasClients bool   `json:"has_clients"`
	IsWireless bool   `json:"is_wireless"`
	NameRank   int    `json:"name_rank"`
	Reason     string `json:"reason"`
}

func DiscoverAPCandidates() ([]IfaceCandidate, error) {
	var out []IfaceCandidate

	hintName := readHNCHint()
	arp := readARPClients()

	ifaces, err := net.Interfaces()
	if err != nil {
		return out, err
	}

	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}

		isHint := hintName != "" && hintName == ifc.Name
		if !isHint && isExcluded(ifc.Name) {
			continue
		}

		ipv4 := firstRFC1918(ifc)
		nameRank := rankAPName(ifc.Name)
		isWifi := isWireless(ifc.Name)
		hasClients := arp[ifc.Name]

		if !isHint && ipv4 == "" && nameRank < 0 && !hasClients {
			continue
		}

		var reasons []string
		if isHint {
			reasons = append(reasons, "hnc_hint")
		}
		if nameRank >= 0 {
			reasons = append(reasons, "name_match")
		}
		if hasClients {
			reasons = append(reasons, "arp_clients")
		}
		if ipv4 != "" {
			reasons = append(reasons, "rfc1918")
		}
		if isWifi {
			reasons = append(reasons, "wireless")
		}

		out = append(out, IfaceCandidate{
			Name:       ifc.Name,
			Index:      ifc.Index,
			IPv4:       ipv4,
			HasClients: hasClients,
			IsWireless: isWifi,
			NameRank:   nameRank,
			Reason:     strings.Join(reasons, ","),
		})
	}

	// Sorting: HNC hint > AP name rank > ARP clients > RFC1918 > wireless > name.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ahint := strings.Contains(a.Reason, "hnc_hint")
		bhint := strings.Contains(b.Reason, "hnc_hint")
		if ahint != bhint {
			return ahint
		}

		ar, br := a.NameRank, b.NameRank
		if ar < 0 {
			ar = 999
		}
		if br < 0 {
			br = 999
		}
		if ar != br {
			return ar < br
		}
		if a.HasClients != b.HasClients {
			return a.HasClients
		}
		if (a.IPv4 != "") != (b.IPv4 != "") {
			return a.IPv4 != ""
		}
		if a.IsWireless != b.IsWireless {
			return a.IsWireless
		}
		return a.Name < b.Name
	})

	return out, nil
}

func isExcluded(name string) bool {
	for _, re := range excludedPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func readHNCHint() string {
	b, err := os.ReadFile(hncHotspotIfaceFile)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) == 0 || len(s) > 32 {
		return ""
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return ""
		}
	}
	return s
}

func firstRFC1918(ifc net.Interface) string {
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if isRFC1918(v4) {
			return v4.String()
		}
	}
	return ""
}

func isRFC1918(ip net.IP) bool {
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
}

func readARPClients() map[string]bool {
	out := make(map[string]bool)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || fields[2] == "0x0" || fields[3] == "00:00:00:00:00:00" {
			continue
		}
		out[fields[5]] = true
	}
	return out
}

func isWireless(name string) bool {
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "wireless")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "phy80211")); err == nil {
		return true
	}
	return false
}

func rankAPName(name string) int {
	n := strings.ToLower(name)
	for i, re := range apNamePatterns {
		if re.MatchString(n) {
			return i
		}
	}
	return -1
}

// InterfaceNets returns every IP+mask configured on the named interface.
// Used by rc29 to tell which end of a flow is the hotspot client (the end
// whose IP falls inside one of these nets) vs the outside world.
//
// For IPv4 we exclude /32 (host route). For IPv6 we exclude /128 (host route)
// and global anycast /127 nonsense, AND we exclude link-local (fe80::/10)
// because every IPv6-capable peer has a link-local, so it'd mis-classify.
// We keep ULA (fc00::/7) and global unicast (2000::/3) — these are what
// real hotspot clients get via SLAAC/DHCPv6-PD.
func InterfaceNets(name string) []*net.IPNet {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if ones == bits {
			continue // host route
		}
		// Skip IPv6 link-local.
		if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		// Normalize: ensure IPNet.IP is the network base (no host bits).
		base := ipnet.IP.Mask(ipnet.Mask)
		out = append(out, &net.IPNet{IP: base, Mask: ipnet.Mask})
	}
	return out
}
