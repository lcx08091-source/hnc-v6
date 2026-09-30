package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── 假系统 ──────────────────────────────────────────────────────

type fakeSys struct {
	mu     sync.Mutex
	hnc    string
	files  map[string]string
	seq    map[string][]string // [采样前, 采样后](按假时钟是否已 Sleep 区分, 与读取次数/并发无关)
	slept  bool
	dirs   map[string][]string
	exists map[string]bool
	cmds   map[string]string
	block  map[string]bool // 该命令一直阻塞到 ctx 超时
	hooks  map[string]func(f *fakeSys)
	env    map[string]string
	now    time.Time
	ctOn   bool
	ctErr  string
	calls  []string
}

func newFakeSys(hnc string) *fakeSys {
	return &fakeSys{hnc: hnc, files: map[string]string{}, seq: map[string][]string{}, dirs: map[string][]string{},
		exists: map[string]bool{}, cmds: map[string]string{}, block: map[string]bool{},
		hooks: map[string]func(*fakeSys){}, env: map[string]string{}}
}

func (f *fakeSys) h(p ...string) string { return filepath.Join(append([]string{f.hnc}, p...)...) }

func (f *fakeSys) scEnv() *scEnv {
	return &scEnv{
		HNCDir: f.hnc, Version: "v5.20-test", SelfPID: 4242, LoopbackPort: 8444,
		CmdTimeout: 300 * time.Millisecond, Budget: 3 * time.Second,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			key := strings.TrimSpace(name + " " + strings.Join(args, " "))
			f.mu.Lock()
			f.calls = append(f.calls, key)
			blk := f.block[key]
			hook := f.hooks[key]
			out, ok := f.cmds[key]
			f.mu.Unlock()
			if blk {
				<-ctx.Done()
				return "", ctx.Err()
			}
			if hook != nil {
				hook(f)
			}
			if !ok {
				return "", errors.New("exec: not found: " + key)
			}
			return out, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if q := f.seq[p]; len(q) > 0 {
				if f.slept && len(q) > 1 {
					return []byte(q[1]), nil
				}
				return []byte(q[0]), nil
			}
			if v, ok := f.files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
		ReadDir: func(p string) ([]string, error) {
			if d, ok := f.dirs[p]; ok {
				return d, nil
			}
			return nil, os.ErrNotExist
		},
		Exists: func(p string) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			_, a := f.files[p]
			_, b := f.dirs[p]
			_, c := f.seq[p]
			return a || b || c || f.exists[p]
		},
		Getenv: func(k string) string { return f.env[k] },
		Now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.now
		},
		Sleep: func(ctx context.Context, d time.Duration) {
			f.mu.Lock()
			f.now = f.now.Add(d)
			f.slept = true
			f.mu.Unlock()
		},
		CtEvents: func() (bool, string) { return f.ctOn, f.ctErr },
	}
}

func props(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&b, "[%s]: [%s]\n", kv[i], kv[i+1])
	}
	return b.String()
}

func gz(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

func procStat(pid int, comm string, utime, stime int) string {
	return fmt.Sprintf("%d (%s) S 1 %d 0 0 -1 4194560 12000 0 0 0 %d %d 0 0 20 0 12 0 1000 123456789 5000 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0",
		pid, comm, pid, utime, stime)
}

var cst = time.FixedZone("CST", 8*3600)

// ─── 夹具 1: realme RMX5010 / ColorOS 16 / 骁龙 8 Elite / SukiSU / GKI 6.6 ────

func fixtureColorOSQualcomm(hnc string) *fakeSys {
	f := newFakeSys(hnc)
	now := time.Date(2026, 9, 30, 14, 30, 0, 0, cst)
	f.now = now
	f.cmds["getprop"] = props(
		"ro.product.brand", "realme", "ro.product.model", "RMX5010", "ro.product.device", "RE5C82L1",
		"ro.product.manufacturer", "realme", "ro.vendor.oplus.market.name", "realme GT 7 Pro",
		"ro.build.version.release", "16", "ro.build.version.sdk", "36",
		"ro.build.display.id", "RMX5010_16.0.0.200(CN01)", "ro.build.version.security_patch", "2026-08-01",
		"ro.build.version.oplusrom", "V16.0.0",
		"ro.soc.manufacturer", "QTI", "ro.soc.model", "SM8750", "ro.board.platform", "sun", "ro.hardware", "qcom",
		"persist.sys.timezone", "Asia/Shanghai", "persist.radio.multisim.config", "dsds",
		"gsm.sim.operator.alpha", "中国移动,中国联通")
	f.files["/proc/sys/kernel/osrelease"] = "6.6.56-android15-8-o-g1234abcd5678\n"
	f.dirs["/data/adb/ksu"] = []string{"bin", "modules.img"}
	f.files["/data/adb/ksud"] = "ELF"
	f.cmds["/data/adb/ksud -V"] = "ksud 3.1.7-SukiSU-Ultra\n"
	f.files["/data/adb/ksu/bin/ksu_susfs"] = "ELF"
	f.dirs["/data/adb/modules"] = []string{"hotspot_network_control", "magic_mount_rs", "susfs4ksu"}
	f.files["/sys/fs/selinux/enforce"] = "1"
	f.files[f.h("run", "service.path")] = "/data/adb/modules/hotspot_network_control\n"
	f.dirs["/data/adb/modules/hotspot_network_control"] = []string{"module.prop"}
	f.dirs[hnc] = []string{"bin", "run", "data"}

	caps := map[string]interface{}{
		"schema": 2, "generated_at": now.Add(-time.Hour).Unix(), "probe": "hotfix17_dummy_sandbox",
		"tc_binary": "/system/bin/tc", "tc_binary_source": "system", "tc_binary_ok": true,
		"tc_version": "tc utility, iproute2-ss171113", "probe_iface_qdisc": "qdisc htb 1: root refcnt 2 r2q 10 default 0x9999",
		"tc_htb": true, "tc_fq_codel": false, "tc_fq_codel_error": "Error: Specified qdisc not found.",
		"tc_cake": false, "tc_cake_error": "Error: Specified qdisc not found.", "tc_netem": true,
		"tc_ingress_supported": true, "tc_clsact_supported": true, "tc_u32_supported": true,
		"tc_police_supported": true, "tc_mirred": true, "tc_ifb_create": true,
		"uplink_mode": "ifb_htb", "downlink_mode": "htb", "qdisc_lowlat_chosen": "sfq",
		"kernel_blocks_clone_vm": true, "selected_launcher": "c_launcher",
		"selinux_avc_denied_recent": 0, "su_domain": "u:r:su:s0",
	}
	cb, _ := json.Marshal(caps)
	f.files[f.h("run", "capabilities.json")] = string(cb)
	f.files[f.h("run", "qdisc_caps.json")] = `{"schema":1,"available":["sfq","pfifo"],"chosen":"sfq",
		"tried":[{"name":"cake","method":"modprobe","ok":false,"err":"not found"},{"name":"fq_codel","ok":false},{"name":"fq","ok":false},{"name":"sfq","ok":true}]}`
	f.files["/proc/net/psched"] = "000003e8 00000040 000f4240 3b9aca00\n"
	f.files["/proc/modules"] = "rmnet_core 262144 3 rmnet_offload,rmnet_shs, Live 0x0000000000000000 (O)\n" +
		"rmnet_offload 45056 0 - Live 0x0000000000000000 (O)\nipam 36864 0 - Live 0x0000000000000000 (O)\n"

	f.cmds["iptables -V"] = "iptables v1.8.7 (legacy)\n"
	f.cmds["ip6tables -V"] = "ip6tables v1.8.7 (legacy)\n"
	f.files["/proc/net/ip_tables_matches"] = "mac\nmark\nconnmark\nconntrack\nstring\ncomment\nlimit\nstate\nudp\ntcp\nicmp\n"
	f.files["/proc/net/ip_tables_targets"] = "MARK\nCONNMARK\nNFLOG\nTEE\nERROR\n"
	f.files["/proc/net/ip6_tables_matches"] = "mac\nmark\nconnmark\nicmp6\n"
	f.cmds["iptables -t mangle -S HNC_MARK"] = "-N HNC_MARK\n" +
		"-A HNC_MARK -m mac --mac-source E2:0D:4A:48:5D:40 -j MARK --set-xmark 0x80003b/0xffffffff\n" +
		"-A HNC_MARK -m mac --mac-source 5A:11:22:33:44:55 -j MARK --set-xmark 0x800001/0xffffffff\n"
	f.cmds["ip6tables -t mangle -S HNC_MARK"] = "-N HNC_MARK\n" +
		"-A HNC_MARK -m mac --mac-source E2:0D:4A:48:5D:40 -j MARK --set-xmark 0x80003b/0xffffffff\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_acct"] = "1\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_events"] = "1\n"
	f.files["/proc/net/nf_conntrack"] = ""
	f.ctOn = true

	f.files[f.h("run", "offload_guard.json")] = fmt.Sprintf(`{"mode":"auto","offload_state":"CAPABLE","fallback_active":false,"since":0,"detail":"tether offload 程序已就位, 当前窗口无流量","last_check":%d,"slowpath":"n/a","clsact":"skip","iface":"wlan2"}`, now.Add(-30*time.Second).Unix())
	f.dirs["/sys/fs/bpf/tethering"] = []string{"map_offload_tether_stats_map", "map_offload_tether_limit_map", "prog_offload_schedcls_tether_upstream4_rawip"}
	f.exists["/dev/ipa"] = true
	f.cmds["pidof ipacm"] = "1234\n"

	f.files[f.h("run", "hnc_state")] = "ACTIVE:wlan2\n"
	f.dirs["/sys/class/net"] = []string{"lo", "wlan0", "wlan1", "wlan2", "rmnet_data0", "rmnet_data1", "rmnet_ipa0", "dummy0", "ifb0", "v4-rmnet_data1"}
	for n, st := range map[string]string{"wlan0": "up", "wlan1": "down", "wlan2": "up", "rmnet_data0": "down", "rmnet_data1": "unknown", "rmnet_ipa0": "unknown", "v4-rmnet_data1": "unknown", "ifb0": "unknown", "lo": "unknown", "dummy0": "down"} {
		f.files["/sys/class/net/"+n+"/operstate"] = st + "\n"
		f.dirs["/sys/class/net/"+n] = []string{"operstate"}
	}
	f.cmds["ip route get 1.1.1.1"] = "1.1.1.1 via 10.11.12.13 dev rmnet_data1 table 1003 src 10.117.193.52 uid 0 \n    cache \n"
	f.cmds["dumpsys tethering"] = "Tethering:\n  Configuration:\n    activeDataSubId: 1\n  Tether state:\n" +
		"    wlan2 - TetheredState - lastError = 0\n    rndis0 - AvailableState - lastError = 0\n" +
		"  Upstream wanted: true\n  Current upstream interface(s): [rmnet_data1, v4-rmnet_data1]\n"
	f.cmds["settings get global multi_sim_data_call"] = "1\n"
	f.cmds["ip -6 addr show dev wlan2"] = "28: wlan2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 3000\n" +
		"    inet6 2409:8963:e03:4493::1/64 scope global \n       valid_lft forever preferred_lft forever\n" +
		"    inet6 fe80::a8bb:ccff:fedd:eeff/64 scope link \n       valid_lft forever preferred_lft forever\n"
	f.files["/proc/sys/net/ipv6/conf/wlan2/disable_ipv6"] = "0\n"
	f.files["/proc/sys/net/ipv6/conf/all/forwarding"] = "1\n"
	f.cmds["cmd wifi help"] = "Wi-Fi (wifi) commands:\n  help or -h\n    Print this help text.\n" +
		"  start-softap <ssid> (open|wpa2|wpa3|wpa3_transition|owe|owe_transition) <passphrase> [-b 2|5|6|any|bridged]\n" +
		"  stop-softap\n    Stop softap (hotspot)\n"

	// IPv6 覆盖: e2 限速(mark 59, 有上行 class), 两个地址只覆盖了一个; 5a 限速(mark 1 → 1:100)全覆盖;
	// 7e 未限速; aa FAILED 不算。
	f.cmds["ip -6 neigh show dev wlan2"] = "2409:8963:e03:4493:a090:ebab:827e:9558 lladdr e2:0d:4a:48:5d:40 REACHABLE\n" +
		"2409:8963:e03:4493:1c2d:3e4f:5a6b:7c8d lladdr e2:0d:4a:48:5d:40 STALE\n" +
		"fe80::e00d:4aff:fe48:5d40 lladdr e2:0d:4a:48:5d:40 router STALE\n" +
		"2409:8963:e03:4493:5811:22ff:fe33:4455 lladdr 5a:11:22:33:44:55 DELAY\n" +
		"2409:8963:e03:4493:9999::1 lladdr 7e:00:00:00:00:09 STALE\n" +
		"2409:8963:e03:4493::dead  FAILED\n"
	f.cmds["tc filter show dev wlan2 parent 1:"] = "filter protocol ip pref 10 u32 chain 0 \n" +
		"filter protocol ip pref 10 u32 chain 0 fh 800: ht divisor 1 \n" +
		"filter protocol ip pref 10 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:59 not_in_hw \n" +
		"  match c0a82b05/ffffffff at 16\n" +
		"filter protocol ipv6 pref 201 u32 chain 0 \n" +
		"filter protocol ipv6 pref 201 u32 chain 0 fh 802: ht divisor 1 \n" +
		"filter protocol ipv6 pref 201 u32 chain 0 fh 802::800 order 2048 key ht 802 bkt 0 flowid 1:100 not_in_hw \n" +
		"  match 24098963/ffffffff at 24\n  match 0e034493/ffffffff at 28\n  match 581122ff/ffffffff at 32\n  match fe334455/ffffffff at 36\n" +
		"filter protocol ipv6 pref 259 u32 chain 0 \n" +
		"filter protocol ipv6 pref 259 u32 chain 0 fh 801: ht divisor 1 \n" +
		"filter protocol ipv6 pref 259 u32 chain 0 fh 801::800 order 2048 key ht 801 bkt 0 flowid 1:59 not_in_hw \n" +
		"  match 24098963/ffffffff at 24\n  match 0e034493/ffffffff at 28\n  match a090ebab/ffffffff at 32\n  match 827e9558/ffffffff at 36\n"
	f.cmds["tc filter show dev ifb0 parent 1:"] = "filter parent 1: protocol ipv6 pref 259 u32 chain 0 fh 801::800 order 2048 key ht 801 bkt 0 flowid 1:59 not_in_hw \n" +
		"  match 24098963/ffffffff at 8\n  match 0e034493/ffffffff at 12\n  match a090ebab/ffffffff at 16\n  match 827e9558/ffffffff at 20\n"
	f.cmds["tc class show dev ifb0"] = "class htb 1:1 root rate 1Gbit ceil 1Gbit burst 1375b cburst 1375b \n" +
		"class htb 1:59 parent 1:1 prio 0 rate 2Mbit ceil 2Mbit burst 1600b cburst 1600b \n"
	f.files[f.h("bin", "hnc_constants.sh")] = "HNC_MARK_BASE=0x800000\nHNC_MARK_MASK=0xff0000\n"

	f.cmds["settings get global auto_time"] = "1\n"
	f.cmds["settings get global auto_time_zone"] = "1\n"
	f.files["/proc/uptime"] = "273600.12 1000000.00\n"

	// 进程: httpd=self; dpid child 活; hotspotd 活; watchdog 不在
	f.seq["/proc/4242/stat"] = []string{procStat(4242, "hnc_httpd", 150, 50), procStat(4242, "hnc_httpd", 151, 50)}
	f.files["/proc/4242/status"] = "Name:\thnc_httpd\nVmRSS:\t   23456 kB\n"
	f.files[f.h("run", "dpid.child.pid")] = "5151\n"
	f.seq["/proc/5151/stat"] = []string{procStat(5151, "hnc_dpid", 1000, 200), procStat(5151, "hnc_dpid", 1020, 210)}
	f.files["/proc/5151/cmdline"] = "/data/local/hnc/bin/hnc_dpid\x00-i\x00wlan2\x00"
	f.files["/proc/5151/status"] = "VmRSS:\t   45678 kB\n"
	f.files[f.h("run", "hotspotd.pid")] = "3131"
	f.files["/proc/3131/stat"] = procStat(3131, "hotspotd", 10, 5)
	f.files["/proc/3131/cmdline"] = "/data/local/hnc/daemon/hotspotd\x00"
	f.files["/proc/3131/status"] = "VmRSS:\t    2048 kB\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_count"] = "1200\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_max"] = "65536\n"
	f.files["/proc/meminfo"] = "MemTotal:       15728640 kB\nMemAvailable:    6291456 kB\n"
	f.files["/proc/loadavg"] = "3.12 2.80 2.55 2/2345 31337\n"

	f.files[f.h("run", "dpi_state.json")] = fmt.Sprintf(`{"schema_version":"2.0","generated_at":%d,"mode":"af_packet","interface":"wlan2","ipv6_capture":true,
		"stats":{"packets":123456,"dns_events":5000,"tls_events":20000},
		"clients":{"c1":{"client_ip":"10.117.193.52","client_mac":"e2:0d:4a:48:5d:40","tls_events":800,"dns_events":400},
		           "c2":{"client_ip":"10.117.193.60","client_mac":"5a:11:22:33:44:55","tls_events":500,"dns_events":3}}}`, now.Add(-5*time.Second).Unix())
	f.files[f.h("run", "dpi_ipname.json")] = `{"entries":{"1.2.3.4":{"name":"a.example.com"},"5.6.7.8":{"name":"b.example.com"},"9.9.9.9":{"name":"c.example.com"}}}`
	f.files[appUsagePath(hnc, now.Format("20060102"))] = `{"date":"20260930","hours":{"10":{"e2:0d:4a:48:5d:40|wechat":[100,900],"e2:0d:4a:48:5d:40|_unknown":[500,500]}},"apps":{}}`
	f.cmds["settings get global private_dns_mode"] = "hostname\n"
	f.cmds["settings get global private_dns_specifier"] = "dns.alidns.com\n"
	return f
}

// ─── 夹具 2: Redmi K70 至尊版 / HyperOS 2 / 天玑 9300+ / Magisk / GKI 6.1 ───

func fixtureMediaTek(hnc string) *fakeSys {
	f := newFakeSys(hnc)
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, cst)
	f.now = now
	f.cmds["getprop"] = props(
		"ro.product.brand", "Redmi", "ro.product.model", "24122RKC7C", "ro.product.device", "rothko",
		"ro.product.manufacturer", "Xiaomi", "ro.product.marketname", "Redmi K70 至尊版",
		"ro.build.version.release", "15", "ro.build.version.sdk", "35",
		"ro.build.display.id", "AQ3A.240912.001", "ro.mi.os.version.name", "OS2.0",
		"ro.soc.manufacturer", "Mediatek", "ro.soc.model", "MT6989", "ro.board.platform", "mt6989", "ro.hardware", "mt6989",
		"persist.sys.timezone", "Asia/Shanghai", "persist.radio.multisim.config", "dsds",
		"gsm.sim.operator.alpha", "CHINA MOBILE,")
	f.files["/proc/sys/kernel/osrelease"] = "6.1.99-android14-11-g0fd1b1f7e7b3-ab12345678\n"
	f.dirs["/data/adb/magisk"] = []string{"busybox", "magisk64"}
	f.cmds["magisk -v"] = "28.1:MAGISK:R\n"
	f.dirs["/data/adb/modules"] = []string{"hotspot_network_control"}
	f.dirs["/data/adb/modules/hotspot_network_control"] = []string{"module.prop"} // 无 service.path → 按默认目录找
	f.files["/sys/fs/selinux/enforce"] = "1"
	f.dirs[hnc] = []string{"bin", "run"}

	caps := map[string]interface{}{
		"schema": 2, "generated_at": now.Add(-10 * time.Minute).Unix(), "probe": "hotfix17_dummy_sandbox",
		"tc_binary": "/system/bin/tc", "tc_binary_source": "system", "tc_binary_ok": true, "tc_version": "tc utility, iproute2-6.1.0",
		"tc_htb": true, "tc_fq_codel": true, "tc_cake": false, "tc_cake_error": "Error: Specified qdisc kind is unknown.",
		"tc_netem": true, "tc_ingress_supported": true, "tc_clsact_supported": true, "tc_u32_supported": true,
		"tc_police_supported": true, "tc_mirred": true, "tc_ifb_create": false,
		"uplink_mode": "police", "downlink_mode": "root_htb", "selinux_avc_denied_recent": 3,
	}
	cb, _ := json.Marshal(caps)
	f.files[f.h("run", "capabilities.json")] = string(cb)
	f.files["/proc/config.gz"] = gz("#\n# Automatically generated file; DO NOT EDIT.\n" +
		"CONFIG_NET_SCH_HTB=y\n# CONFIG_IFB is not set\nCONFIG_NET_SCH_SFQ=y\nCONFIG_NET_SCH_FQ=y\n" +
		"CONFIG_NET_SCH_FQ_CODEL=y\n# CONFIG_NET_SCH_CAKE is not set\nCONFIG_NET_CLS_BPF=y\nCONFIG_NET_CLS_FW=y\n" +
		"CONFIG_NETFILTER_XT_MATCH_STRING=m\nCONFIG_NETFILTER_XT_MATCH_LIMIT=y\n" +
		"# CONFIG_NETFILTER_XT_MATCH_CONNMARK is not set\n# CONFIG_NETFILTER_XT_CONNMARK is not set\n" +
		"CONFIG_NETFILTER_XT_TARGET_NFLOG=y\nCONFIG_HZ=250\n")
	f.files["/proc/net/psched"] = "000003e8 00000040 000f4240 3b9aca00\n"
	f.files["/proc/modules"] = "mtk_mddp 204800 1 ccmni, Live 0x0000000000000000 (OE)\nccmni 98304 2 mtk_mddp, Live 0x0 (OE)\n"

	f.cmds["iptables -V"] = "iptables v1.8.8 (legacy)\n"
	f.files["/proc/net/ip_tables_matches"] = "mac\nmark\nconntrack\ncomment\n"
	f.files["/proc/net/ip_tables_targets"] = "MARK\nCONNMARK\nERROR\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_acct"] = "0\n"
	f.files["/proc/net/nf_conntrack"] = ""
	f.ctErr = "bind: permission denied"

	f.files[f.h("run", "offload_guard.json")] = fmt.Sprintf(`{"mode":"auto","offload_state":"ACTIVE","fallback_active":false,"detail":"hotspotd 不可达, 未能施加兜底","last_check":%d}`, now.Add(-20*time.Second).Unix())
	f.dirs["/sys/fs/bpf/tethering"] = []string{"map_offload_tether_stats_map"}
	f.exists["/dev/mddp"] = true

	f.files[f.h("run", "hnc_state")] = "ACTIVE:ap0\n"
	f.dirs["/sys/class/net"] = []string{"lo", "wlan0", "ap0", "ccmni0", "ccmni1", "ifb0"}
	for n, st := range map[string]string{"wlan0": "up", "ap0": "up", "ccmni0": "down", "ccmni1": "up", "ifb0": "down", "lo": "unknown"} {
		f.files["/sys/class/net/"+n+"/operstate"] = st + "\n"
		f.dirs["/sys/class/net/"+n] = []string{"operstate"}
	}
	f.cmds["ip route get 1.1.1.1"] = "1.1.1.1 dev ccmni1 table ccmni1 src 10.0.0.2 uid 0 \n    cache \n"
	f.block["dumpsys tethering"] = true // 慢 ROM: 超时
	f.cmds["ip -6 addr show dev ap0"] = "30: ap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet6 fe80::1/64 scope link \n"
	f.cmds["cmd wifi help"] = "Wi-Fi (wifi) commands:\n  help\n  set-wifi-enabled enabled|disabled\n"
	f.cmds["ip -6 neigh show dev ap0"] = ""
	f.cmds["settings get global auto_time"] = "0\n"
	f.files["/proc/uptime"] = "600.5 100.0\n"

	f.seq["/proc/4242/stat"] = []string{procStat(4242, "hnc_httpd", 10, 5)}
	f.files["/proc/4242/status"] = "VmRSS:\t   19000 kB\n"
	f.files[f.h("run", "dpid.pid")] = "777"
	f.files["/proc/777/stat"] = procStat(777, "hnc_dpid", 50, 10)
	f.files["/proc/777/cmdline"] = "/data/local/hnc/bin/hnc_dpid\x00"
	f.files["/proc/777/status"] = "VmRSS:\t   30000 kB\n"
	// hotspotd.pid 指向一个已被复用的 PID(别的进程)→ 不算
	f.files[f.h("run", "hotspotd.pid")] = "888"
	f.files["/proc/888/stat"] = procStat(888, "kworker/u16:2", 0, 0)
	f.files["/proc/888/cmdline"] = "com.android.phone\x00"
	f.files["/proc/sys/net/netfilter/nf_conntrack_count"] = "60000\n"
	f.files["/proc/sys/net/netfilter/nf_conntrack_max"] = "65536\n"
	f.files["/proc/meminfo"] = "MemAvailable:     150000 kB\n"
	f.cmds["settings get global private_dns_mode"] = "opportunistic\n"
	return f
}

// ─── 工具 ────────────────────────────────────────────────────────

func findItem(t *testing.T, r *scReport, sec, id string) scItem {
	t.Helper()
	for _, s := range r.Sections {
		if s.ID != sec {
			continue
		}
		for _, it := range s.Items {
			if it.ID == id {
				return it
			}
		}
		t.Fatalf("item %s/%s not found; items=%+v", sec, id, s.Items)
	}
	t.Fatalf("section %s not found", sec)
	return scItem{}
}

func expectStatus(t *testing.T, r *scReport, sec, id, want string) scItem {
	t.Helper()
	it := findItem(t, r, sec, id)
	if it.Status != want {
		t.Errorf("%s/%s status=%s want %s (value=%q detail=%q)", sec, id, it.Status, want, it.Value, it.Detail)
	}
	return it
}

func mustContain(t *testing.T, what, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("%s: %q does not contain %q", what, s, sub)
	}
}

// ─── 端到端(假系统) ─────────────────────────────────────────────

func TestSelfcheckColorOSQualcomm(t *testing.T) {
	f := fixtureColorOSQualcomm("/data/local/hnc")
	r := runSelfcheck(f.scEnv(), scOptions{})

	if len(r.Sections) != 9 {
		t.Fatalf("sections=%d", len(r.Sections))
	}
	wantIDs := []string{"system", "shaping", "firewall", "offload", "network", "ipv6", "time", "process", "ident"}
	for i, s := range r.Sections {
		if s.ID != wantIDs[i] || s.Title == "" {
			t.Errorf("section %d = %s/%s", i, s.ID, s.Title)
		}
	}
	if r.Version != "v5.20-test" || r.GeneratedAt == 0 {
		t.Errorf("header: %+v", r)
	}

	mustContain(t, "model", findItem(t, r, "system", "device_model").Value, "realme RMX5010(realme GT 7 Pro)")
	mustContain(t, "rom", findItem(t, r, "system", "rom").Value, "ColorOS V16.0.0")
	mustContain(t, "soc", findItem(t, r, "system", "soc").Value, "高通 Qualcomm · SM8750(sun)")
	mustContain(t, "kernel", expectStatus(t, r, "system", "kernel", scOK).Value, "GKI android15-6.6")
	root := expectStatus(t, r, "system", "root", scOK)
	if root.Value != "SukiSU" {
		t.Errorf("root=%q", root.Value)
	}
	mustContain(t, "root detail", root.Detail, "SuSFS: 已安装")
	mustContain(t, "root detail", root.Detail, "magic_mount_rs")
	mustContain(t, "selinux", findItem(t, r, "system", "selinux").Value, "Enforcing")
	expectStatus(t, r, "system", "module_path", scOK)
	expectStatus(t, r, "system", "webui_entry", scOK)
	expectStatus(t, r, "system", "fork_compat", scInfo)

	expectStatus(t, r, "shaping", "cap_probe", scOK)
	expectStatus(t, r, "shaping", "tc_binary", scOK)
	mustContain(t, "psched", findItem(t, r, "shaping", "psched").Value, "高精度")
	expectStatus(t, r, "shaping", "tc_htb", scOK)
	expectStatus(t, r, "shaping", "tc_u32", scOK)
	expectStatus(t, r, "shaping", "tc_ifb", scOK)
	expectStatus(t, r, "shaping", "tc_sfq", scOK) // 来自 qdisc_caps 实测
	cake := expectStatus(t, r, "shaping", "tc_cake", scInfo)
	mustContain(t, "cake detail", cake.Detail, "Specified qdisc not found")
	if it := findItem(t, r, "shaping", "tc_fw"); it.Value != "未知" {
		t.Errorf("fw without config.gz should be unknown, got %q", it.Value)
	}
	lat := expectStatus(t, r, "shaping", "low_latency", scInfo)
	mustContain(t, "lowlat", lat.Value, "sfq")
	expectStatus(t, r, "shaping", "uplink_mode", scOK)
	expectStatus(t, r, "shaping", "downlink_mode", scOK)

	expectStatus(t, r, "firewall", "iptables", scOK)
	expectStatus(t, r, "firewall", "xt_mac", scOK)
	expectStatus(t, r, "firewall", "xt_NFLOG", scOK)
	mustContain(t, "chain", expectStatus(t, r, "firewall", "hnc_chain", scOK).Value, "2 条")
	expectStatus(t, r, "firewall", "conntrack_acct", scOK)
	mustContain(t, "ct", expectStatus(t, r, "firewall", "conntrack_events", scOK).Value, "精确")

	expectStatus(t, r, "offload", "offload_guard", scOK)
	mustContain(t, "bpf", findItem(t, r, "offload", "tether_bpf").Value, "3 个")
	ipa := findItem(t, r, "offload", "qcom_ipa")
	mustContain(t, "ipa", ipa.Detail, "ipacm 运行中")
	mustContain(t, "ipa", ipa.Detail, "ipam")

	mustContain(t, "hotspot", expectStatus(t, r, "network", "hotspot_iface", scOK).Value, "wlan2(up)")
	mustContain(t, "cand", findItem(t, r, "network", "iface_candidates").Value, "wlan1(down)")
	if u := expectStatus(t, r, "network", "upstream", scOK); u.Value != "热点上游 rmnet_data1(蜂窝)" {
		t.Errorf("upstream=%q", u.Value)
	}
	teth := findItem(t, r, "network", "tethering")
	mustContain(t, "teth", teth.Value, "wlan2")
	mustContain(t, "teth", teth.Detail, "rmnet_data1")
	mustContain(t, "cell", findItem(t, r, "network", "cellular").Value, "rmnet_data1")
	sim := findItem(t, r, "network", "dual_sim")
	mustContain(t, "sim", sim.Value, "双卡设备(dsds), 已插 2 张")
	expectStatus(t, r, "network", "hotspot_ipv6", scOK)
	expectStatus(t, r, "network", "softap_cmd", scOK)

	// IPv6 覆盖: e2 下行 1/2 上行 1/2; 5a 全覆盖(1:100); 共 2 个未覆盖
	mustContain(t, "v6", findItem(t, r, "ipv6", "v6_neigh").Value, "3 台设备有 IPv6 全局地址, 其中 2 台已限速")
	if it := expectStatus(t, r, "ipv6", "v6_uncovered", scWarn); it.Value != "2" {
		t.Errorf("uncovered=%q", it.Value)
	}
	e2 := expectStatus(t, r, "ipv6", "v6_dev_e20d4a485d40", scWarn)
	if e2.Value != "下行 1/2 · 上行 1/2" {
		t.Errorf("e2 value=%q", e2.Value)
	}
	mustContain(t, "e2", e2.Detail, "下行未覆盖: 2409:8963:e03:4493:1c2d:3e4f:5a6b:7c8d")
	mustContain(t, "e2", e2.Detail, "上行未覆盖: 2409:8963:e03:4493:1c2d:3e4f:5a6b:7c8d")
	a5 := expectStatus(t, r, "ipv6", "v6_dev_5a1122334455", scOK)
	if a5.Value != "下行 1/1 · 上行未限速" {
		t.Errorf("5a value=%q", a5.Value)
	}

	expectStatus(t, r, "time", "clock", scOK)
	mustContain(t, "tz", expectStatus(t, r, "time", "timezone", scOK).Value, "Asia/Shanghai")
	expectStatus(t, r, "time", "auto_time", scOK)
	if up := findItem(t, r, "time", "uptime"); up.Value != "3 天 4 小时" {
		t.Errorf("uptime=%q", up.Value)
	}

	h := expectStatus(t, r, "process", "proc_httpd", scOK)
	mustContain(t, "httpd", h.Value, "PID 4242")
	mustContain(t, "httpd", h.Value, "CPU 1.0%")
	d := expectStatus(t, r, "process", "proc_dpid", scOK)
	mustContain(t, "dpid", d.Value, "CPU 30.0%")
	mustContain(t, "dpid", d.Value, "44.6 MB")
	expectStatus(t, r, "process", "proc_hotspotd", scOK)
	expectStatus(t, r, "process", "proc_watchdog", scWarn)
	expectStatus(t, r, "process", "conntrack_usage", scOK)

	expectStatus(t, r, "ident", "dpid_running", scOK)
	expectStatus(t, r, "ident", "dpi_state", scOK)
	mustContain(t, "ipname", findItem(t, r, "ident", "ipname_entries").Value, "3 条")
	mustContain(t, "unknown", expectStatus(t, r, "ident", "unknown_ratio", scOK).Value, "50%")
	mustContain(t, "pdns", findItem(t, r, "ident", "private_dns").Value, "dns.alidns.com")
	enc := expectStatus(t, r, "ident", "encrypted_dns", scWarn)
	mustContain(t, "enc", enc.Value, "1/2")
	mustContain(t, "enc", enc.Detail, "5a:11:22:33:44:55")

	s := r.Summary
	total := 0
	for _, sec := range r.Sections {
		total += len(sec.Items)
	}
	if s.OK+s.Warn+s.Fail+s.Info != total || s.Fail != 0 || s.Warn == 0 {
		t.Errorf("summary=%+v total=%d", s, total)
	}
	// 只读: 不应调用任何写操作类命令
	for _, c := range f.calls {
		for _, bad := range []string{" add ", " del ", " replace ", "-A ", "-D ", "-I ", " put ", "start-softap x"} {
			if strings.Contains(" "+c+" ", bad) {
				t.Errorf("mutating command issued: %q", c)
			}
		}
	}
}

func TestSelfcheckMediaTek(t *testing.T) {
	f := fixtureMediaTek("/data/local/hnc")
	r := runSelfcheck(f.scEnv(), scOptions{})

	mustContain(t, "rom", findItem(t, r, "system", "rom").Value, "HyperOS OS2.0")
	mustContain(t, "soc", findItem(t, r, "system", "soc").Value, "联发科 MediaTek · MT6989")
	mustContain(t, "kernel", findItem(t, r, "system", "kernel").Value, "GKI android14-6.1")
	root := expectStatus(t, r, "system", "root", scOK)
	if root.Value != "Magisk" {
		t.Errorf("root=%q", root.Value)
	}
	mustContain(t, "root", root.Detail, "28.1:MAGISK:R")
	w := expectStatus(t, r, "system", "webui_entry", scInfo)
	mustContain(t, "webui", w.Fix, "http://127.0.0.1:8444")
	expectStatus(t, r, "system", "selinux", scWarn) // 3 条 avc denied
	expectStatus(t, r, "system", "module_path", scOK)

	mustContain(t, "kcfg", findItem(t, r, "shaping", "kernel_config").Value, "可读")
	ifb := expectStatus(t, r, "shaping", "tc_ifb", scWarn)
	mustContain(t, "ifb", ifb.Detail, "实测失败")
	expectStatus(t, r, "shaping", "tc_sfq", scOK) // =y
	mustContain(t, "sfq", findItem(t, r, "shaping", "tc_sfq").Detail, "内核内建")
	expectStatus(t, r, "shaping", "tc_fw", scOK)
	expectStatus(t, r, "shaping", "tc_fq_codel", scOK)
	if it := findItem(t, r, "shaping", "low_latency"); it.Value != "fq_codel" {
		t.Errorf("lowlat=%q", it.Value)
	}
	expectStatus(t, r, "shaping", "uplink_mode", scWarn)
	expectStatus(t, r, "shaping", "downlink_mode", scInfo)

	expectStatus(t, r, "firewall", "ip6tables", scWarn) // 命令缺失
	expectStatus(t, r, "firewall", "xt_connmark", scWarn)
	mustContain(t, "string", expectStatus(t, r, "firewall", "xt_string", scInfo).Value, "首次使用时加载")
	expectStatus(t, r, "firewall", "xt_NFLOG", scInfo)
	expectStatus(t, r, "firewall", "hnc_chain", scInfo)
	expectStatus(t, r, "firewall", "conntrack_acct", scWarn)
	ce := expectStatus(t, r, "firewall", "conntrack_events", scInfo)
	mustContain(t, "ct", ce.Detail, "permission denied")

	g := expectStatus(t, r, "offload", "offload_guard", scWarn)
	if g.Fix == "" {
		t.Error("offload ACTIVE without fallback should carry a fix")
	}
	mt := expectStatus(t, r, "offload", "mtk_hwnat", scWarn)
	mustContain(t, "mtk", mt.Detail, "/dev/mddp")
	mustContain(t, "mtk", mt.Detail, "mtk_mddp")
	for _, sec := range r.Sections {
		for _, it := range sec.Items {
			if it.ID == "qcom_ipa" {
				t.Error("qcom_ipa should not be shown on MediaTek without IPA traces")
			}
		}
	}

	mustContain(t, "hotspot", findItem(t, r, "network", "hotspot_iface").Value, "ap0(up)")
	if u := findItem(t, r, "network", "upstream"); u.Value != "ccmni1" {
		t.Errorf("upstream=%q", u.Value)
	}
	mustContain(t, "teth timeout", findItem(t, r, "network", "tethering").Value, "不可用")
	mustContain(t, "cell", findItem(t, r, "network", "cellular").Value, "ccmni1")
	mustContain(t, "sim", findItem(t, r, "network", "dual_sim").Value, "已插 1 张 · 数据卡: 卡1 CHINA MOBILE")
	mustContain(t, "v6", findItem(t, r, "network", "hotspot_ipv6").Value, "未下发")
	expectStatus(t, r, "network", "softap_cmd", scWarn)

	expectStatus(t, r, "ipv6", "v6_uncovered", scInfo)
	expectStatus(t, r, "time", "auto_time", scWarn)

	expectStatus(t, r, "process", "proc_hotspotd", scFail) // PID 被复用, 不算活
	expectStatus(t, r, "process", "proc_dpid", scOK)
	expectStatus(t, r, "process", "conntrack_usage", scFail)
	expectStatus(t, r, "process", "mem_available", scWarn)

	expectStatus(t, r, "ident", "dpi_state", scWarn)
	expectStatus(t, r, "ident", "unknown_ratio", scInfo)
	if r.Summary.Fail < 2 {
		t.Errorf("summary=%+v", r.Summary)
	}
}

func TestSelfcheckTimeoutSection(t *testing.T) {
	f := fixtureColorOSQualcomm("/data/local/hnc")
	env := f.scEnv()
	env.Budget = 200 * time.Millisecond
	defs := []scSectionDef{
		{"fast", "快", func(c *scCtx) []scItem { return []scItem{{ID: "a", Label: "A", Status: scOK, Value: "1"}} }},
		{"slow", "慢", func(c *scCtx) []scItem { <-c.ctx.Done(); time.Sleep(50 * time.Millisecond); return nil }},
		{"boom", "炸", func(c *scCtx) []scItem { panic("x") }},
	}
	start := time.Now()
	r := runSelfcheckDefs(env, scOptions{}, defs)
	if time.Since(start) > 2*time.Second {
		t.Fatal("budget not enforced")
	}
	expectStatus(t, r, "fast", "a", scOK)
	expectStatus(t, r, "slow", "slow_timeout", scWarn)
	expectStatus(t, r, "boom", "boom_panic", scWarn)
}

func TestSelfcheckCommandTimeoutIsolated(t *testing.T) {
	// 单条命令阻塞只拖慢本条(CmdTimeout), 整体仍在预算内完成
	f := fixtureColorOSQualcomm("/data/local/hnc")
	f.block["getprop"] = true
	env := f.scEnv()
	start := time.Now()
	r := runSelfcheck(env, scOptions{})
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %s", el)
	}
	expectStatus(t, r, "system", "device_model", scWarn)
	expectStatus(t, r, "shaping", "tc_htb", scOK) // 其他分区不受影响
}

func TestSelfcheckReprobe(t *testing.T) {
	f := fixtureMediaTek("/data/local/hnc")
	delete(f.files, f.h("run", "capabilities.json"))
	script := f.h("bin", "capability_probe.sh")
	f.files[script] = "#!/system/bin/sh"
	f.cmds["sh "+script] = ""
	f.hooks["sh "+script] = func(f *fakeSys) {
		f.mu.Lock()
		f.files[f.h("run", "capabilities.json")] = `{"generated_at":1,"tc_htb":true,"tc_binary_ok":true,"uplink_mode":"ifb_htb","downlink_mode":"htb"}`
		f.mu.Unlock()
	}
	r := runSelfcheck(f.scEnv(), scOptions{})
	mustContain(t, "note", findItem(t, r, "shaping", "cap_probe").Detail, "重新探测")
	expectStatus(t, r, "shaping", "uplink_mode", scOK)
	n := 0
	for _, c := range f.calls {
		if c == "sh "+script {
			n++
		}
	}
	if n != 1 {
		t.Errorf("capability_probe ran %d times, want exactly 1 (shared across sections)", n)
	}
}

func TestSelfcheckBadClock(t *testing.T) {
	f := fixtureColorOSQualcomm("/data/local/hnc")
	f.now = time.Date(2019, 1, 1, 8, 0, 0, 0, cst)
	r := runSelfcheck(f.scEnv(), scOptions{})
	it := expectStatus(t, r, "time", "clock", scFail)
	if it.Fix == "" {
		t.Error("bad clock needs a fix hint")
	}
}

// ─── 纯函数 / 分类 ──────────────────────────────────────────────

func TestSelfcheckStatusClassification(t *testing.T) {
	cases := []struct{ state, imp, want string }{
		{"yes", "required", scOK}, {"no", "required", scFail}, {"no", "recommended", scWarn},
		{"no", "optional", scInfo}, {"maybe", "required", scInfo}, {"unknown", "required", scInfo},
	}
	for _, c := range cases {
		if got := scFeatureStatus(c.state, c.imp); got != c.want {
			t.Errorf("scFeatureStatus(%s,%s)=%s want %s", c.state, c.imp, got, c.want)
		}
	}
	ct := []struct {
		n, m float64
		want string
	}{{100, 1000, scOK}, {749, 1000, scOK}, {750, 1000, scWarn}, {900, 1000, scFail}, {1, 0, scInfo}}
	for _, c := range ct {
		if got := scConntrackStatus(c.n, c.m); got != c.want {
			t.Errorf("conntrack %v/%v=%s want %s", c.n, c.m, got, c.want)
		}
	}
	f := scTCFeatures[0] // htb
	if st, src := scResolveFeature(f, map[string]interface{}{"tc_htb": false}, nil, map[string]string{"NET_SCH_HTB": "y"}, nil); st != "no" || !strings.Contains(src, "实测") {
		t.Errorf("probe result must win over kconfig: %s %s", st, src)
	}
	if st, _ := scResolveFeature(f, nil, nil, map[string]string{"NET_SCH_HTB": "m"}, map[string]bool{}); st != "maybe" {
		t.Errorf("=m unloaded → maybe, got %s", st)
	}
	if st, _ := scResolveFeature(f, nil, nil, map[string]string{"NET_SCH_HTB": "m"}, map[string]bool{"sch_htb": true}); st != "yes" {
		t.Errorf("loaded module → yes, got %s", st)
	}
	if st, _ := scResolveFeature(f, nil, nil, nil, nil); st != "unknown" {
		t.Errorf("no info → unknown, got %s", st)
	}
	r := &scReport{Sections: []scSection{{Items: []scItem{{Status: scOK}, {Status: scWarn}, {Status: scFail}, {Status: scInfo}, {Status: scOK}}}}}
	if s := scSummarize(r.Sections); s != (scSummary{OK: 2, Warn: 1, Fail: 1, Info: 1}) {
		t.Errorf("summary=%+v", s)
	}
}

func TestSelfcheckDetectors(t *testing.T) {
	roms := []struct {
		p    map[string]string
		want string
	}{
		{map[string]string{"ro.build.version.oplusrom": "V15.0.0"}, "ColorOS"},
		{map[string]string{"ro.build.version.oplusrom": "V15.0.0", "ro.product.brand": "OnePlus"}, "ColorOS/OxygenOS"},
		{map[string]string{"ro.mi.os.version.name": "OS2.0"}, "HyperOS"},
		{map[string]string{"ro.miui.ui.version.name": "V140"}, "MIUI"},
		{map[string]string{"ro.build.version.oneui": "60101"}, "One UI"},
		{map[string]string{"ro.vivo.os.name": "OriginOS", "ro.vivo.os.version": "5.0"}, "OriginOS"},
		{map[string]string{"ro.product.brand": "google"}, "Pixel(原生)"},
		{map[string]string{}, "AOSP/其他"},
	}
	for _, c := range roms {
		if got := scDetectROM(c.p); got.Name != c.want {
			t.Errorf("rom %v → %q want %q", c.p, got.Name, c.want)
		}
	}
	if v := scDetectROM(map[string]string{"ro.build.version.oneui": "60101"}).Ver; v != "6.1.1" {
		t.Errorf("oneui ver=%q", v)
	}
	socs := []struct {
		p    map[string]string
		want string
	}{
		{map[string]string{"ro.soc.manufacturer": "QTI", "ro.soc.model": "SM8750"}, "qualcomm"},
		{map[string]string{"ro.board.platform": "taro"}, "qualcomm"},
		{map[string]string{"ro.soc.manufacturer": "Mediatek"}, "mediatek"},
		{map[string]string{"ro.board.platform": "mt6893"}, "mediatek"},
		{map[string]string{"ro.board.platform": "s5e9945"}, "samsung"},
		{map[string]string{"ro.hardware": "exynos2400"}, "samsung"},
		{map[string]string{"ro.board.platform": "ums9230"}, "unisoc"},
		{map[string]string{"ro.soc.manufacturer": "Google", "ro.soc.model": "Tensor G4"}, "google"},
		{map[string]string{"ro.board.platform": "zuma"}, "google"},
		{map[string]string{"ro.board.platform": "foo"}, "unknown"},
	}
	for _, c := range socs {
		if got := scSoCVendor(c.p); got != c.want {
			t.Errorf("soc %v → %s want %s", c.p, got, c.want)
		}
	}
	if g, ok := scKernelInfo("5.10.198-android12-9-00085-g2f7ad2d7e7a6-ab11136126"); !ok || g != "android12-5.10" {
		t.Errorf("gki=%q %v", g, ok)
	}
	if _, ok := scKernelInfo("4.19.157-perf+"); ok {
		t.Error("non-GKI misdetected")
	}
	tethered, up := scParseTethering("  Tether state:\n    wlan2 - TetheredState - lastError = 0\n    ap0 - LocalHotspotState - lastError = 0\n  Current upstream interface(s): [wlan0]\n")
	if strings.Join(tethered, ",") != "wlan2,ap0" || up != "[wlan0]" {
		t.Errorf("tethering=%v %q", tethered, up)
	}
	if st, ok := scParseProcStat("123 (my (weird) proc) S 1 2 3 4 5 6 7 8 9 10 77 23 0 0"); !ok || st != 100 {
		t.Errorf("procstat=%d %v", st, ok)
	}
	kc := scParseKconfig("CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\nCONFIG_D=\"str\"\n")
	if kc["A"] != "y" || kc["B"] != "m" || kc["C"] != "n" || kc["D"] != "str" {
		t.Errorf("kconfig=%v", kc)
	}
}

func TestSelfcheckIPv6CoverageParsing(t *testing.T) {
	f := fixtureColorOSQualcomm("/x")
	eg := scParseTCv6Filters(f.cmds["tc filter show dev wlan2 parent 1:"])
	if len(eg) != 2 {
		t.Fatalf("egress v6 filters=%+v", eg)
	}
	if eg[1].Addr != "2409:8963:e03:4493:a090:ebab:827e:9558" || eg[1].Dir != "dst" || eg[1].FlowID != "1:59" || eg[1].Pref != "259" {
		t.Errorf("egress[1]=%+v", eg[1])
	}
	in := scParseTCv6Filters(f.cmds["tc filter show dev ifb0 parent 1:"])
	if len(in) != 1 || in[0].Dir != "src" {
		t.Errorf("ingress=%+v", in)
	}
	neigh := scParseNeighV6(f.cmds["ip -6 neigh show dev wlan2"])
	if len(neigh) != 3 || len(neigh["e2:0d:4a:48:5d:40"]) != 2 {
		t.Errorf("neigh=%v", neigh)
	}
	marks := scParseMarkRules(f.cmds["iptables -t mangle -S HNC_MARK"])
	if marks["e2:0d:4a:48:5d:40"] != 0x80003b || marks["5a:11:22:33:44:55"] != 0x800001 {
		t.Errorf("marks=%v", marks)
	}
	// 错 class: 地址的 filter 指向别人的 class
	wrong := []scV6Filter{{Addr: "2409:8963:e03:4493:5811:22ff:fe33:4455", Dir: "dst", FlowID: "1:59"}}
	devs := scIPv6Coverage(map[string][]string{"5a:11:22:33:44:55": {"2409:8963:e03:4493:5811:22ff:fe33:4455"}},
		marks, nil, wrong, nil, map[string]bool{}, 0x800000)
	if len(devs) != 1 || len(devs[0].DownWrong) != 1 || devs[0].Class != "1:100" {
		t.Errorf("wrong class not detected: %+v", devs)
	}
	// 老 iproute2 的 --set-mark 写法
	if m := scParseMarkRules("-A HNC_MARK -m mac --mac-source aa:bb:cc:dd:ee:ff -j MARK --set-mark 8388610"); m["aa:bb:cc:dd:ee:ff"] != 0x800002 {
		t.Errorf("set-mark decimal=%v", m)
	}
}

// ─── 脱敏 ────────────────────────────────────────────────────────

func TestSelfcheckRedaction(t *testing.T) {
	cases := []struct{ in, want string }{
		{"设备 e2:0d:4a:48:5d:40", "设备 xx:xx:xx:xx:5d:40"},
		{"MAC E2-0D-4A-48-5D-40.", "MAC xx:xx:xx:xx:5d:40."},
		{"v6_dev_e20d4a485d40", "v6_dev_xxxxxxxx5d40"},
		{"下行未覆盖: 2409:8963:e03:4493:1c2d:3e4f:5a6b:7c8d 2409:8963::1", "下行未覆盖: 2409:8963:* 2409:8963:*"},
		{"fe80::e00d:4aff:fe48:5d40/64", "fe80:0:*/64"},
		{"src 10.117.193.52 via 192.168.43.1", "src 10.117.*.* via 192.168.*.*"},
		{"http://127.0.0.1:8444 and ::1 and 0.0.0.0", "http://127.0.0.1:8444 and ::1 and 0.0.0.0"},
		{"时间 2026-09-30 14:30:00 +0800", "时间 2026-09-30 14:30:00 +0800"},
		{"iptables v1.8.7 · 6.6.56-android15 · class 1:59 · 0x80003b", "iptables v1.8.7 · 6.6.56-android15 · class 1:59 · 0x80003b"},
		{"[rmnet_data1, v4-rmnet_data1]", "[rmnet_data1, v4-rmnet_data1]"},
	}
	for _, c := range cases {
		if got := scRedactText(c.in); got != c.want {
			t.Errorf("redact(%q)=%q want %q", c.in, got, c.want)
		}
	}

	f := fixtureColorOSQualcomm("/data/local/hnc")
	r := runSelfcheck(f.scEnv(), scOptions{})
	red := redactReport(r)
	b, _ := json.Marshal(red)
	for _, leak := range []string{"e2:0d:4a:48:5d:40", "5a:11:22:33:44:55", "827e:9558", "1c2d:3e4f", "10.117.193", "e20d4a485d40"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("redacted report leaks %q", leak)
		}
	}
	if !red.Redacted || r.Redacted {
		t.Error("redacted flag wrong / original mutated")
	}
	ob, _ := json.Marshal(r)
	if !strings.Contains(string(ob), "e2:0d:4a:48:5d:40") {
		t.Error("original report must stay unredacted")
	}
	txt := renderSelfcheckText(red)
	for _, want := range []string{"HNC 自检报告", "【设备与系统】", "【IPv6 覆盖】", "! 设备 xx:xx:xx:xx:5d:40:", "· 机型: realme RMX5010", "(已脱敏"} {
		mustContain(t, "text", txt, want)
	}
	for _, ln := range strings.Split(txt, "\n") {
		if strings.HasPrefix(ln, "✗") || strings.HasPrefix(ln, "!") || strings.HasPrefix(ln, "✓") || strings.HasPrefix(ln, "·") {
			if strings.Count(ln, "\n") != 0 {
				t.Error("item spans multiple lines")
			}
		}
	}
}

// ─── HTTP / action / 导出 ───────────────────────────────────────

func resetSelfcheckState() {
	selfcheckState.mu.Lock()
	selfcheckState.last, selfcheckState.loaded, selfcheckState.busy = nil, false, false
	selfcheckState.mu.Unlock()
}

func TestSelfcheckAPIAndExport(t *testing.T) {
	dir := t.TempDir()
	resetSelfcheckState()
	defer resetSelfcheckState()
	old := selfcheckEnvFactory
	defer func() { selfcheckEnvFactory = old }()
	selfcheckEnvFactory = func(h string) *scEnv { return fixtureColorOSQualcomm(h).scEnv() }
	s := newServer(dir)

	// 无缓存
	rec := httptest.NewRecorder()
	s.apiSelfcheck(rec, httptest.NewRequest("GET", "/api/selfcheck", nil))
	var empty map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &empty)
	if empty["available"] != false {
		t.Fatalf("empty=%s", rec.Body.String())
	}

	// run
	resp, ok := dispatchSelfcheckAction(s, "selfcheck_run", map[string]string{})
	if !ok || !resp.OK {
		t.Fatalf("run=%+v", resp)
	}
	var rep scReport
	if err := json.Unmarshal([]byte(resp.Detail), &rep); err != nil || len(rep.Sections) != 9 {
		t.Fatalf("run detail: %v", err)
	}
	if _, err := os.Stat(selfcheckCachePath(dir)); err != nil {
		t.Errorf("cache not persisted: %v", err)
	}

	// GET 缓存 + redact
	rec = httptest.NewRecorder()
	s.apiSelfcheck(rec, httptest.NewRequest("GET", "/api/selfcheck?redact=1", nil))
	body := rec.Body.String()
	for _, want := range []string{`"available":true`, `"running":false`, `"sections":[`, `"summary":{"ok":`, `"redacted":true`} {
		mustContain(t, "GET", body, want)
	}
	if strings.Contains(body, "e2:0d:4a:48:5d:40") {
		t.Error("GET ?redact=1 leaks MAC")
	}

	// 重启后从 run/selfcheck.json 恢复
	resetSelfcheckState()
	if selfcheckCached(dir) == nil {
		t.Error("cache not reloaded from disk")
	}

	// export(默认脱敏)
	resp, _ = dispatchSelfcheckAction(s, "selfcheck_export", map[string]string{})
	if !resp.OK {
		t.Fatalf("export=%+v", resp)
	}
	var ex map[string]interface{}
	_ = json.Unmarshal([]byte(resp.Detail), &ex)
	name, _ := ex["name"].(string)
	jname, _ := ex["json_name"].(string)
	if !strings.HasPrefix(name, "hnc-selfcheck-") || !strings.HasSuffix(name, ".txt") || ex["redacted"] != true {
		t.Fatalf("export detail=%v", ex)
	}
	txt, err := os.ReadFile(filepath.Join(dir, "exports", name))
	if err != nil || !strings.Contains(string(txt), "HNC 自检报告") || strings.Contains(string(txt), "e2:0d:4a:48:5d:40") {
		t.Errorf("export txt bad: %v", err)
	}
	jb, _ := os.ReadFile(filepath.Join(dir, "exports", jname))
	if !json.Valid(jb) || strings.Contains(string(jb), "5a:11:22:33:44:55") {
		t.Error("export json invalid or unredacted")
	}

	// /api/exports 列表可见 + 下载 content-type
	rec = httptest.NewRecorder()
	s.apiExportList(rec, httptest.NewRequest("GET", "/api/exports", nil))
	mustContain(t, "exports list", rec.Body.String(), name)
	mustContain(t, "exports list", rec.Body.String(), jname)
	rec = httptest.NewRecorder()
	s.apiExportFile(rec, httptest.NewRequest("GET", "/api/exports/"+name, nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("download code=%d ct=%s", rec.Code, rec.Header().Get("Content-Type"))
	}
	// 其他 .txt 不能借道下载
	_ = os.WriteFile(filepath.Join(dir, "exports", "secret.txt"), []byte("x"), 0600)
	rec = httptest.NewRecorder()
	s.apiExportFile(rec, httptest.NewRequest("GET", "/api/exports/secret.txt", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("non-selfcheck txt served: %d", rec.Code)
	}

	// 不脱敏导出
	time.Sleep(1100 * time.Millisecond) // 文件名精确到秒
	resp, _ = dispatchSelfcheckAction(s, "selfcheck_export", map[string]string{"redact": "0"})
	_ = json.Unmarshal([]byte(resp.Detail), &ex)
	txt, _ = os.ReadFile(filepath.Join(dir, "exports", ex["name"].(string)))
	if ex["redacted"] != false || !strings.Contains(string(txt), "e2:0d:4a:48:5d:40") {
		t.Error("redact=0 should keep MACs")
	}

	// 忙
	selfcheckState.running.Lock()
	resp, _ = dispatchSelfcheckAction(s, "selfcheck_run", nil)
	selfcheckState.running.Unlock()
	if resp.OK || resp.Error != "busy" || selfcheckActionStatus(resp) != http.StatusConflict {
		t.Errorf("busy=%+v", resp)
	}
	if _, ok := dispatchSelfcheckAction(s, "rule_set", nil); ok {
		t.Error("non-selfcheck action claimed")
	}
}

func TestSelfcheckExportPrune(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 13; i++ {
		for _, ext := range []string{".txt", ".json"} {
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("hnc-selfcheck-20260930-1200%02d%s", i, ext)), []byte("x"), 0600)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "hnc-export-20260101-000000.zip"), []byte("x"), 0600)
	pruneSelfcheckExports(dir, 10)
	ents, _ := os.ReadDir(dir)
	if len(ents) != 21 {
		t.Errorf("after prune %d files, want 21", len(ents))
	}
	if _, err := os.Stat(filepath.Join(dir, "hnc-selfcheck-20260930-120000.txt")); err == nil {
		t.Error("oldest not pruned")
	}
}

func TestSelfcheckMtkHwnatStateReuse(t *testing.T) {
	f := fixtureMediaTek("/data/local/hnc")
	f.files[f.h("run", "mtk_hwnat.json")] = `{"experimental":true,"detected":true,"paths":["/proc/hnat"],"action":"disabled","detail":"hook_toggle=0"}`
	r := runSelfcheck(f.scEnv(), scOptions{})
	it := expectStatus(t, r, "offload", "mtk_hwnat", scOK)
	mustContain(t, "hwnat", it.Value, "已由 HNC 关闭")
	mustContain(t, "hwnat", it.Detail, "hook_toggle=0")
}
