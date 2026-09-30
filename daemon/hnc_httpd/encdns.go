// encdns.go — v5.21 加密 DNS 策略(执行见 bin/encdns_sync.sh)
//
//   data/encdns.json: {"policy":"off|dot|strict","devices":{"<mac>":"off|dot|strict"},"ts":N}
//
//   动作 encdns_set {policy, scope?, mac?}
//     scope=global(默认; 带 mac 时默认 device): policy ∈ off|dot|strict
//     scope=device: mac 必填; policy ∈ off|dot|strict|inherit(inherit = 删掉覆盖, 跟随全局)
//     写文件后同步跑 encdns_sync.sh, detail 为脚本最后一行(ENCDNS=...)
//
//   GET /api/encdns →
//     {ok, policy, devices:{mac:policy}, policies:[...], string_layer: available|unavailable|unknown,
//      counters:{chain,v6,dot:{pkts,bytes},doh_ip:{..},doh_sni:{..},doh_dns:{..},total_pkts,total_bytes,v4_pkts,v6_pkts} | null,
//      counters_error?, dpid:{dns_seen,dot_attempts,dot_flows,doh_suspect,...} | null, tradeoff, updated_at}
//     counters 是 iptables 规则计数(每次重同步清零), 包数 ≈ 被挡下的加密 DNS 尝试次数。
//
// 取舍: dot/strict 下, 「私人 DNS = 指定主机名」(严格模式)的设备不会回落明文 DNS,
// 会整体无法解析(= 断网)。这台设备单独设 off, 或让用户把私人 DNS 改回「自动」。

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const encdnsTradeoff = "拦截加密 DNS 后, Android「私人 DNS=自动」、浏览器「安全 DNS=自动」会回落到明文 DNS, 热点能看到每次解析, 应用识别与域名封锁更准。" +
	"代价: 把「私人 DNS」设成「指定主机名」(严格模式)的设备不会回落, 会完全无法解析域名(相当于断网) —— 请让它改回「自动」, 或单独给这台设备设为「关闭」。" +
	"strict 另外拦截公共 DoH 服务器(dns.google、cloudflare-dns.com、dns.alidns.com、doh.pub 等), 少数自带 DoH 且不回落的 App 可能无法联网。"

const encdnsMaxDevices = 64

var encdnsPolicies = []string{"off", "dot", "strict"}

type encdnsConf struct {
	Policy  string            `json:"policy"`
	Devices map[string]string `json:"devices"`
	Ts      int64             `json:"ts,omitempty"`
}

var encdnsMu sync.Mutex

func encdnsPath(hncDir string) string { return filepath.Join(hncDir, "data", "encdns.json") }

func validEncdnsPolicy(p string) bool { return p == "off" || p == "dot" || p == "strict" }

func loadEncdns(hncDir string) encdnsConf {
	c := encdnsConf{Policy: "off", Devices: map[string]string{}}
	b, err := os.ReadFile(encdnsPath(hncDir))
	if err != nil {
		return c
	}
	var x encdnsConf
	if json.Unmarshal(b, &x) != nil {
		return c
	}
	if validEncdnsPolicy(x.Policy) {
		c.Policy = x.Policy
	}
	for m, p := range x.Devices {
		m = strings.ToLower(strings.TrimSpace(m))
		if validMAC(m) && validEncdnsPolicy(p) {
			c.Devices[m] = p
		}
	}
	c.Ts = x.Ts
	return c
}

func actionEncdnsSet(s *server, p map[string]string) actionResp {
	policy := strings.ToLower(strings.TrimSpace(p["policy"]))
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	scope := strings.ToLower(strings.TrimSpace(p["scope"]))
	if scope == "" {
		scope = "global"
		if mac != "" {
			scope = "device"
		}
	}
	encdnsMu.Lock()
	defer encdnsMu.Unlock()
	c := loadEncdns(s.hncDir)
	switch scope {
	case "global":
		if !validEncdnsPolicy(policy) {
			return actionResp{OK: false, Error: "bad params", Detail: "policy must be off|dot|strict"}
		}
		if c.Policy == policy {
			return actionResp{OK: true, Detail: "no change"}
		}
		c.Policy = policy
	case "device":
		if !validMAC(mac) {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
		}
		if dpiCtlSkipMAC(mac) {
			return actionResp{OK: false, Error: "bad params", Detail: "模拟设备不下发 iptables"}
		}
		switch {
		case policy == "inherit" || policy == "":
			if _, ok := c.Devices[mac]; !ok {
				return actionResp{OK: true, Detail: "no change"}
			}
			delete(c.Devices, mac)
		case validEncdnsPolicy(policy):
			if c.Devices[mac] == policy {
				return actionResp{OK: true, Detail: "no change"}
			}
			if _, ok := c.Devices[mac]; !ok && len(c.Devices) >= encdnsMaxDevices {
				return actionResp{OK: false, Error: "too many", Detail: "按设备覆盖已达上限 64"}
			}
			c.Devices[mac] = policy
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "policy must be off|dot|strict|inherit"}
		}
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "scope must be global|device"}
	}
	c.Ts = time.Now().Unix()
	b, _ := json.Marshal(c)
	if err := discoverWriteAtomic(encdnsPath(s.hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	encdnsCountersInvalidate()
	rc, out := runBin(s.hncDir, "encdns_sync.sh")
	out = lastLine(strings.TrimSpace(out))
	if rc != 0 {
		return actionResp{OK: false, Error: "encdns sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

// ─── 计数(iptables -nvxL, 2 秒缓存)──────────────────────────────────

var encdnsCnt struct {
	mu  sync.Mutex
	at  time.Time
	v   map[string]interface{}
	err string
}

func encdnsCountersInvalidate() {
	encdnsCnt.mu.Lock()
	encdnsCnt.at = time.Time{}
	encdnsCnt.mu.Unlock()
}

func (s *server) encdnsCounters() (map[string]interface{}, string) {
	encdnsCnt.mu.Lock()
	defer encdnsCnt.mu.Unlock()
	if !encdnsCnt.at.IsZero() && time.Since(encdnsCnt.at) < 2*time.Second {
		return encdnsCnt.v, encdnsCnt.err
	}
	encdnsCnt.at = time.Now()
	encdnsCnt.v, encdnsCnt.err = nil, ""
	rc, out := runBin(s.hncDir, "encdns_sync.sh", "--counters")
	line := lastLine(strings.TrimSpace(out))
	if rc != 0 {
		encdnsCnt.err = line
		return nil, line
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		encdnsCnt.err = "bad counters output"
		return nil, encdnsCnt.err
	}
	encdnsCnt.v = m
	return m, ""
}

// encdnsStringLayer xt_string 能力(strict 的 SNI/DNS 名字层): available | unavailable | unknown
func encdnsStringLayer(hncDir string) string {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "encdns_caps.json"))
	if err != nil {
		return connBlockDNSLayer(hncDir) // 同一个内核能力, conn_blocks 探测过也算数
	}
	var c struct {
		L *bool `json:"string_layer"`
	}
	if json.Unmarshal(b, &c) != nil || c.L == nil {
		return "unknown"
	}
	if *c.L {
		return "available"
	}
	return "unavailable"
}

// dpid 在 dpi_state.json 里的 encdns 计数(被动观测, 与策略无关)
func (s *server) encdnsDpid() interface{} {
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json"))
	if err != nil {
		return nil
	}
	root, _ := raw.(map[string]interface{})
	if v, ok := root["encdns"].(map[string]interface{}); ok {
		return v
	}
	return nil
}

// GET /api/encdns
func (s *server) apiEncdns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	c := loadEncdns(s.hncDir)
	macs := make([]string, 0, len(c.Devices))
	for m := range c.Devices {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	devs := make([]map[string]string, 0, len(macs))
	for _, m := range macs {
		devs = append(devs, map[string]string{"mac": m, "policy": c.Devices[m]})
	}
	resp := map[string]interface{}{
		"ok": true, "policy": c.Policy, "devices": c.Devices, "device_list": devs,
		"policies": encdnsPolicies, "string_layer": encdnsStringLayer(s.hncDir),
		"tradeoff": encdnsTradeoff, "updated_at": c.Ts, "dpid": s.encdnsDpid(),
	}
	cnt, errStr := s.encdnsCounters()
	resp["counters"] = cnt
	if errStr != "" {
		resp["counters_error"] = errStr
	}
	writeJSON(w, http.StatusOK, resp)
}
