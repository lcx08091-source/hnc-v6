package output

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// 名单必须与 data/encdns_resolvers.txt(bin/encdns_sync.sh 用的那份)逐条一致
func TestEncDNSListMatchesDataFile(t *testing.T) {
	p := filepath.Join("..", "..", "..", "data", "encdns_resolvers.txt")
	f, err := os.Open(p)
	if err != nil {
		t.Skipf("data file not reachable: %v", err)
	}
	defer f.Close()
	var hosts, addrs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" {
			continue
		}
		l = strings.Fields(l)[0]
		if strings.Contains(l, ":") || net.ParseIP(l) != nil || strings.Contains(l, "/") {
			addrs = append(addrs, l)
		} else {
			hosts = append(hosts, l)
		}
	}
	eq := func(a, b []string) bool {
		a, b = append([]string(nil), a...), append([]string(nil), b...)
		sort.Strings(a)
		sort.Strings(b)
		return strings.Join(a, ",") == strings.Join(b, ",")
	}
	if !eq(hosts, DoHHosts) {
		t.Fatalf("hosts differ:\nfile=%v\ncode=%v", hosts, DoHHosts)
	}
	if !eq(addrs, DoHAddrs) {
		t.Fatalf("addrs differ:\nfile=%v\ncode=%v", addrs, DoHAddrs)
	}
	if len(dohNets) != len(DoHAddrs) {
		t.Fatalf("unparsable addr in DoHAddrs: %d/%d", len(dohNets), len(DoHAddrs))
	}
}

func TestIsDoHHostAddr(t *testing.T) {
	for n, want := range map[string]bool{
		"dns.google": true, "DNS.Google.": true, "dns64.dns.google": true, "cloudflare-dns.com": true,
		"mozilla.cloudflare-dns.com": true, "doh.pub": true, "notdoh.pub": false, "google.com": false, "": false,
	} {
		if got := IsDoHHost(n); got != want {
			t.Errorf("IsDoHHost(%q)=%v", n, got)
		}
	}
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "223.5.5.5": true, "45.90.28.77": true, "2400:3200::1": true, "2400:3200:0::1": true,
		"8.8.8.9": false, "104.16.249.249": false, "junk": false,
	} {
		if got := IsDoHAddr(ip); got != want {
			t.Errorf("IsDoHAddr(%q)=%v", ip, got)
		}
	}
}

func TestConntrackDoTKey(t *testing.T) {
	l := "ipv4     2 tcp      6 10 SYN_SENT src=192.168.43.10 dst=8.8.8.8 sport=40000 dport=853 [UNREPLIED] src=8.8.8.8 dst=10.0.0.2 sport=853 dport=40000 mark=0 use=1"
	if k := ConntrackDoTKey(l); k != "tcp|192.168.43.10|40000|8.8.8.8" {
		t.Fatal(k)
	}
	u := "ipv6     10 udp      17 29 src=2408::1 dst=2400:3200::1 sport=5000 dport=853 src=2400:3200::1 dst=2408::1 sport=853 dport=5000 use=1"
	if k := ConntrackDoTKey(u); k != "udp|2408::1|5000|2400:3200::1" {
		t.Fatal(k)
	}
	// 应答方向的 sport=853 不算(客户端 853 端口发起的普通连接)
	r := "ipv4     2 tcp      6 10 ESTABLISHED src=192.168.43.10 dst=1.2.3.4 sport=853 dport=443 src=1.2.3.4 dst=10.0.0.2 sport=443 dport=853 use=1"
	if k := ConntrackDoTKey(r); k != "" {
		t.Fatal(k)
	}
	if ConntrackDoTKey("garbage") != "" {
		t.Fatal("garbage")
	}
}

func TestEncDNSCountersInState(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "dpi_state.json"), "test")
	now := time.Unix(1_790_000_000, 0)
	w.RecordDNS("aa:bb:cc:00:00:01", "192.168.43.10", "192.168.43.1", "www.qq.com", now)
	w.RecordDNS("aa:bb:cc:00:00:01", "192.168.43.10", "192.168.43.1", "www.qq.com", now)
	w.RecordTLS("aa:bb:cc:00:00:01", "192.168.43.10", "142.250.1.1", "dns.google", "", now)
	w.RecordTLS("aa:bb:cc:00:00:01", "192.168.43.10", "1.1.1.1", "", "", now)
	w.RecordTLS("aa:bb:cc:00:00:01", "192.168.43.10", "5.5.5.5", "www.qq.com", "", now)
	w.ObserveDoTFlows(map[string]struct{}{"tcp|a|1|b": {}, "tcp|a|2|b": {}})
	w.ObserveDoTFlows(map[string]struct{}{"tcp|a|2|b": {}, "udp|a|3|c": {}})
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "dpi_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		EncDNS *EncDNSState `json:"encdns"`
	}
	if err := json.Unmarshal(b, &st); err != nil || st.EncDNS == nil {
		t.Fatalf("encdns missing: %v %s", err, b)
	}
	e := st.EncDNS
	if e.DNSSeen != 2 || e.DoHSuspect != 2 || e.DoTAttempts != 3 || e.DoTFlows != 2 || e.Since == 0 {
		t.Fatalf("counters: %+v", e)
	}
	if len(e.RecentDoH) != 2 || e.RecentDoH[0].Name != "dns.google" || e.RecentDoH[1].Name != "1.1.1.1" || e.RecentDoH[0].ClientMAC != "aa:bb:cc:00:00:01" {
		t.Fatalf("recent: %+v", e.RecentDoH)
	}
}
