// hostname_junk_test.go — v5.30 T1b: 垃圾主机名当作没有名字(名单本身见 hnc.io/dpid/hostname)。
//
// 「改动前会失败」: v5.29 cleanHostname 只去不可打印字符, DHCP option 12 =
// "null" 时 Hostname == "null"(TestDHCPJunkOpt12FallsBackToFQDN /
// TestDHCPJunkOpt12Only 都失败)。
package capture

import (
	"net"
	"testing"
)

// dhcpWithOpts DHCP REQUEST, 客户端 clientMAC, 附加给定选项。
func dhcpWithOpts(opts ...[]byte) []byte {
	bootp := make([]byte, 236)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	copy(bootp[28:34], clientMAC)
	all := [][]byte{u32(dhcpMagic), {53, 1, 3}}
	all = append(all, opts...)
	all = append(all, []byte{255})
	return ipv4UDP(clientMAC, net.IPv4zero, net.IPv4bcast, 68, 67, cat(bootp, cat(all...)))
}

// 接线: 走真实的 parsePacket → parseDHCPv4 → cleanHostname。
func TestDHCPJunkOpt12FallsBackToFQDN(t *testing.T) {
	fq := cat([]byte{0x04, 0, 0}, wireName("Real-PC.lan"))
	pkt := dhcpWithOpts(cat([]byte{12, 4}, []byte("null")), cat([]byte{81, byte(len(fq))}, fq))
	if h := mustHint(t, pkt); h.Hostname != "Real-PC" {
		t.Fatalf("option 12 = null 应退到 option 81: hostname=%q", h.Hostname)
	}
}

func TestDHCPJunkOpt12Only(t *testing.T) {
	for _, name := range []string{"null", "localhost", "(none)", "123"} {
		pkt := dhcpWithOpts(cat([]byte{12, byte(len(name))}, []byte(name)))
		if h := mustHint(t, pkt); h.Hostname != "" {
			t.Errorf("option 12 = %q: hostname=%q, want 空", name, h.Hostname)
		}
	}
}

func TestLocalHostnameJunk(t *testing.T) {
	if got := localHostname("localhost.local"); got != "" {
		t.Fatalf("mDNS localhost.local → %q, want 空", got)
	}
	if got := localHostname("MacBook-Pro.local"); got != "MacBook-Pro" {
		t.Fatalf("真名被误挡: %q", got)
	}
}
