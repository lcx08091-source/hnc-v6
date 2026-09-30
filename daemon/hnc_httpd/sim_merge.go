// sim_merge.go — 模拟环境: 把模拟设备合并进各只读接口(字段形状与真实条目一致,
// 额外带 "sim":true)。每个入口先看 simActive()(一个 atomic 读), 关闭时原样返回。
//
// 合并点: /api/devices, /api/live(含 ?devices=1), /api/events(SSE 定时推 changed),
// /api/connections(汇总 counts 与 ?mac= 明细), /api/app_usage, /api/stats(legacy),
// /api/usage_month, /api/online_hours, /api/dpi_history, /api/dpi_state(clients),
// /api/app_limits。

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *server) simViews(now time.Time) ([]simView, int64) {
	if !s.simActive() {
		return nil, 0
	}
	return simFor(s.hncDir).snapshot(now)
}

func simAppIDName(d *simDevice) (id, name, cat string) {
	if d.AppID == "" {
		return appUnknownID, "未识别", ""
	}
	name = d.AppName
	if name == "" {
		name = d.AppID
	}
	return d.AppID, name, d.Category
}

// simDeviceMap 生成与 buildDevicesPayload 真实条目同形的设备行
func simDeviceMap(v *simView, now int64) map[string]interface{} {
	d := &v.D
	hn, src := d.Hostname, "dhcp"
	if d.Name != "" {
		hn, src = d.Name, "manual"
	}
	status := "allowed"
	if d.Blocked {
		status = "blocked"
	}
	lastSeen := now
	if d.Offline {
		lastSeen = now - 600
	}
	m := map[string]interface{}{
		"mac":           d.MAC,
		"ip":            d.IP,
		"hostname":      hn,
		"hostname_src":  src,
		"iface":         "sim",
		"vendor":        d.Vendor,
		"rx_bytes":      v.Down,
		"tx_bytes":      v.Up,
		"status":        status,
		"last_seen":     lastSeen,
		"online":        !d.Offline,
		"down_mbps":     d.LimitDownMbps,
		"up_mbps":       d.LimitUpMbps,
		"limit_enabled": d.LimitDownMbps > 0 || d.LimitUpMbps > 0,
		"delay_ms":      d.DelayMs,
		"jitter_ms":     d.JitterMs,
		"loss_pct":      d.LossPct,
		"delay_enabled": d.DelayMs > 0 || d.JitterMs > 0 || d.LossPct > 0,
		"sqm_enabled":   d.SQM,
		"whitelist":     d.Whitelist,
		"rx_bps":        v.Rx,
		"tx_bps":        v.Tx,
		"sim":           true,
		"sim_type":      d.Type,
	}
	ident := map[string]interface{}{
		"type":         simIdentType(d.Type),
		"brand":        d.Vendor,
		"confidence":   90,
		"hostname":     d.Hostname,
		"hostname_src": "dhcp",
		"last_seen":    lastSeen,
	}
	if os := simOS(d.Type, d.Vendor); os != "" {
		ident["os"] = os
	}
	if len(d.Ident) > 0 {
		for _, k := range []string{"type", "os", "os_ver", "brand", "model"} {
			if val, set := d.Ident[k]; set {
				if val == "" {
					delete(ident, k)
				} else {
					ident[k] = val
				}
			}
		}
		ident["confidence"] = 100
		ident["manual"] = true
	}
	m["ident"] = ident
	id, name, cat := simAppIDName(d)
	if d.AppID != "" {
		m["dpi_apps"] = []map[string]interface{}{{
			"name": name, "category": cat, "confidence": "high", "id": id,
			"count": 20 + int(v.Down/(1<<20))%500, "last_seen": lastSeen,
		}}
	}
	if bps := v.Rx + v.Tx; d.AppID != "" && bps >= liveAppMinBps {
		m["live_apps"] = []map[string]interface{}{{
			"id": id, "name": name, "bps": bps, "category": cat, "share": 1.0, "system": appTier(cat) == tierSystem,
		}}
	}
	return m
}

// simAppendDevices 追加模拟设备到 /api/devices 列表(与真实 MAC 重复的跳过)
func (s *server) simAppendDevices(out []map[string]interface{}, seen map[string]bool) []map[string]interface{} {
	now := time.Now()
	views, _ := s.simViews(now)
	for i := range views {
		if seen[views[i].D.MAC] {
			continue
		}
		seen[views[i].D.MAC] = true
		out = append(out, simDeviceMap(&views[i], now.Unix()))
	}
	return out
}

// ─── 连接 ─────────────────────────────────────────────────────────────

var simIPFirstOctets = []int{36, 39, 42, 47, 58, 59, 60, 101, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223}

// simFakeIP 按 (seed, 域名) 稳定生成一个公网样子的 IPv4
func simFakeIP(seed int64, key string) string {
	h := func(i int64) int { return int(simHash(seed, key, "ip", i) * 256) }
	a := simIPFirstOctets[int(simHash(seed, key, "ip0", 0)*float64(len(simIPFirstOctets)))]
	return fmt.Sprintf("%d.%d.%d.%d", a, h(1), h(2), 1+h(3)%254)
}

type simConn struct {
	proto, host, ip, nameSrc string
	dport, sport             int
	weight                   float64
	app                      bool
	age                      float64 // 连接已存在秒数(决定累计字节)
}

func simConnsFor(v *simView, seed int64, lib func(id string) (simApp, bool)) []simConn {
	d := &v.D
	var doms []string
	if a, ok := lib(d.AppID); ok {
		doms = a.Domains
	} else if d.AppID != "" {
		doms = []string{d.AppID + ".com"}
	}
	video := d.Category == "video" || d.Category == "live"
	game := d.Category == "game"
	var out []simConn
	wsum := 0.0
	for i, dom := range doms {
		c := simConn{proto: "tcp", host: dom, dport: 443, nameSrc: "sni", app: true}
		if i > 0 && !strings.HasPrefix(dom, "api.") && strings.Count(dom, ".") == 1 {
			c.host = []string{"api.", "img.", "v.", "cdn."}[i%4] + dom
		}
		if i == 0 && video {
			c.proto, c.nameSrc = "udp", "dns" // QUIC 看不到 SNI, 走 DNS 关联
		}
		if i == 0 && game {
			c.proto, c.nameSrc = "udp", "dns"
			c.dport = 10000 + int(simHash(seed, d.MAC, "gport", 0)*20000)
		}
		c.weight = 1 / float64(i+1) * (0.6 + 0.8*simHash(seed, d.MAC+dom, "w", 0))
		wsum += c.weight
		c.ip = simFakeIP(seed, c.host)
		out = append(out, c)
	}
	for i := range out {
		if wsum > 0 {
			out[i].weight = out[i].weight / wsum * 0.97
		}
	}
	// 背景连接: DNS / NTP(几乎没流量)
	out = append(out,
		simConn{proto: "udp", host: "dns.alidns.com", ip: "223.5.5.5", dport: 53, nameSrc: "dns", weight: 0.02},
		simConn{proto: "udp", host: "ntp.aliyun.com", ip: simFakeIP(seed, "ntp.aliyun.com"), dport: 123, nameSrc: "dns", weight: 0.01},
	)
	for i := range out {
		out[i].sport = 32768 + int(simHash(seed, d.MAC+out[i].host, "sport", 0)*28000)
		out[i].age = 30 + simHash(seed, d.MAC+out[i].host, "age", 0)*1800
	}
	return out
}

func simConnBlocked(blocks []connBlock, host, ip string) bool {
	for _, b := range blocks {
		switch b.Kind {
		case "ip":
			if b.Value == ip {
				return true
			}
		case "domain":
			if host == b.Value || strings.HasSuffix(host, "."+b.Value) {
				return true
			}
		}
	}
	return false
}

// simConnections /api/connections?mac=<模拟 MAC> 的完整响应; 不是模拟设备返回 false
func (s *server) simConnections(mac string) (map[string]interface{}, bool) {
	if !isSimMAC(mac) {
		return nil, false
	}
	now := time.Now()
	views, seed := s.simViews(now)
	var v *simView
	for i := range views {
		if views[i].D.MAC == mac {
			v = &views[i]
		}
	}
	if v == nil {
		return nil, false
	}
	d := &v.D
	lib := func(id string) (simApp, bool) { return simFindApp(s.hncDir, id) }
	type grp struct {
		n   int
		b   uint64
		bps int64
	}
	groups := map[string]*grp{}
	list := []map[string]interface{}{}
	var totUp, totDn uint64
	var totBps int64
	if !d.Blocked && !d.Offline {
		_, appName, _ := simAppIDName(d)
		for _, c := range simConnsFor(v, seed, lib) {
			blocked := simConnBlocked(d.ConnBlocks, c.host, c.ip)
			up, dn := int64(float64(v.Tx)*c.weight), int64(float64(v.Rx)*c.weight)
			if blocked {
				up, dn = 0, 0
			}
			avg := float64(d.RxBps+d.TxBps) * c.weight
			dnB := uint64(avg * c.age * 0.9)
			upB := uint64(float64(d.TxBps) * c.weight * c.age)
			if c.dport == 53 || c.dport == 123 {
				dnB, upB = uint64(200+c.sport%800), uint64(80+c.sport%300)
			}
			item := map[string]interface{}{
				"proto": c.proto, "dst": c.ip, "dport": c.dport, "sport": c.sport,
				"up_bytes": upB, "down_bytes": dnB, "up_bps": up, "down_bps": dn,
				"v6": false, "name": c.host, "name_src": c.nameSrc, "sim": true,
			}
			if c.proto == "tcp" {
				item["state"] = "ESTABLISHED"
				item["ttl"] = 431000 + c.sport%999
			} else {
				item["ttl"] = 30 + c.sport%150
			}
			label := ""
			if c.app && d.AppID != "" {
				item["app"], item["app_id"] = appName, d.AppID
				label = appName
			}
			if svc := wellKnownSvc(c.proto, c.dport); svc != "" {
				item["svc"] = svc
				if label == "" {
					label = svc
				}
			}
			if blocked {
				item["blocked"] = true
			}
			if label == "" {
				label = "未识别"
			}
			g := groups[label]
			if g == nil {
				g = &grp{}
				groups[label] = g
			}
			g.n++
			g.b += upB + dnB
			g.bps += up + dn
			totUp += upB
			totDn += dnB
			totBps += up + dn
			list = append(list, item)
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		bi := list[i]["up_bps"].(int64) + list[i]["down_bps"].(int64)
		bj := list[j]["up_bps"].(int64) + list[j]["down_bps"].(int64)
		return bi > bj
	})
	gl := make([]map[string]interface{}, 0, len(groups))
	for label, g := range groups {
		gl = append(gl, map[string]interface{}{"label": label, "n": g.n, "bytes": g.b, "bps": g.bps})
	}
	sort.Slice(gl, func(i, j int) bool {
		bi, bj := gl[i]["bps"].(int64), gl[j]["bps"].(int64)
		if bi != bj {
			return bi > bj
		}
		return gl[i]["bytes"].(uint64) > gl[j]["bytes"].(uint64)
	})
	var blocks []connBlock
	if len(d.ConnBlocks) > 0 {
		blocks = d.ConnBlocks
	}
	return map[string]interface{}{
		"ok": true, "ts": now.Unix(), "readable": true, "acct": true,
		"mac": mac, "ips": []string{d.IP}, "blocks": blocks,
		"total": len(list), "conns": list, "groups": gl,
		"up_bytes": totUp, "down_bytes": totDn, "bps": totBps, "sim": true,
	}, true
}

// simMergeConnCounts /api/connections 汇总模式: counts[mac] = {n, bps}
func (s *server) simMergeConnCounts(counts map[string]map[string]interface{}) {
	views, seed := s.simViews(time.Now())
	lib := func(id string) (simApp, bool) { return simFindApp(s.hncDir, id) }
	for i := range views {
		v := &views[i]
		if v.D.Blocked || v.D.Offline {
			continue
		}
		n := len(simConnsFor(v, seed, lib))
		counts[v.D.MAC] = map[string]interface{}{"n": n, "bps": float64(v.Rx + v.Tx), "sim": true}
	}
}

// ─── 统计类 ───────────────────────────────────────────────────────────

// simMergeStats /api/stats(legacy): today → 按小时叠加; 其它 range → 今日那一格叠加今日合计
func (s *server) simMergeStats(rangeParam, macFilter string, buckets []Bucket) []Bucket {
	now := time.Now()
	views, _ := s.simViews(now)
	if len(views) == 0 {
		return buckets
	}
	todayLabel := now.Format("01-02")
	for i := range views {
		v := &views[i]
		if macFilter != "" && macFilter != v.D.MAC {
			continue
		}
		if rangeParam == "today" {
			for h := 0; h < 24 && h < len(buckets); h++ {
				buckets[h].RX += int64(v.Hours[h][0])
				buckets[h].TX += int64(v.Hours[h][1])
			}
			continue
		}
		for j := len(buckets) - 1; j >= 0; j-- {
			if buckets[j].Label == todayLabel {
				buckets[j].RX += int64(v.Down)
				buckets[j].TX += int64(v.Up)
				break
			}
		}
	}
	return buckets
}

// simMergeAppUsageDay /api/app_usage: 今天那一天叠加模拟设备的 (小时, mac|app) 累计。
// d 为 nil(今天还没有真实数据)时新建一天。非今天 / 关闭时原样返回。
func (s *server) simMergeAppUsageDay(d *appUsageDay, date string) *appUsageDay {
	now := time.Now()
	if date != now.Format("20060102") {
		return d
	}
	views, _ := s.simViews(now)
	if len(views) == 0 {
		return d
	}
	if d == nil {
		d = &appUsageDay{Date: date, Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
	}
	if d.Hours == nil {
		d.Hours = map[string]map[string][2]uint64{}
	}
	if d.Apps == nil {
		d.Apps = map[string]appUsageMeta{}
	}
	for i := range views {
		v := &views[i]
		id, name, cat := simAppIDName(&v.D)
		d.Apps[id] = appUsageMeta{Name: name, Category: cat}
		for h := 0; h < 24; h++ {
			if v.Hours[h][0] == 0 && v.Hours[h][1] == 0 {
				continue
			}
			hk := strconv.Itoa(h)
			if d.Hours[hk] == nil {
				d.Hours[hk] = map[string][2]uint64{}
			}
			mk := v.D.MAC + "|" + id
			c := d.Hours[hk][mk]
			c[0] += v.Hours[h][1] // up
			c[1] += v.Hours[h][0] // down
			d.Hours[hk][mk] = c
		}
	}
	return d
}

// simHistRows /api/dpi_history: 每台模拟设备每小时一行(今天), 落在 [from, to] 内
func (s *server) simHistRows(fromTs, toTs int64, macFilter string) []histRow {
	now := time.Now()
	views, _ := s.simViews(now)
	if len(views) == 0 {
		return nil
	}
	midnight := localDayStart(now).Unix()
	var rows []histRow
	for i := range views {
		v := &views[i]
		if macFilter != "" && macFilter != v.D.MAC {
			continue
		}
		id, name, cat := simAppIDName(&v.D)
		if v.D.AppID == "" {
			id, name, cat = "", "", ""
		}
		for h := 0; h < 24; h++ {
			if v.Hours[h][0] == 0 && v.Hours[h][1] == 0 {
				continue
			}
			ts := midnight + int64(h)*3600 + 1800
			if ts > toTs {
				ts = toTs
			}
			if ts < fromTs {
				continue
			}
			rows = append(rows, histRow{Ts: ts, MAC: v.D.MAC, App: name, AppID: id, Cat: cat,
				RX: v.Hours[h][0], TX: v.Hours[h][1]})
		}
	}
	return rows
}

// simMergeUsageMonth /api/usage_month: 今日累计 + 本月此前每天的估算(基准速率 × 作息均值 × 1 天 × 日波动)。
// 不改动缓存里的原 map, 开启时返回拷贝。
func (s *server) simMergeUsageMonth(out map[string]interface{}) map[string]interface{} {
	now := time.Now()
	views, seed := s.simViews(now)
	if len(views) == 0 {
		return out
	}
	devs := map[string]interface{}{}
	if b, err := json.Marshal(out["devices"]); err == nil {
		_ = json.Unmarshal(b, &devs)
	}
	var mean float64
	for _, w := range simDiurnal {
		mean += w
	}
	mean /= 24
	for i := range views {
		v := &views[i]
		rx, tx := float64(v.Down), float64(v.Up)
		if !v.D.Blocked && !v.D.Offline {
			for day := 1; day < now.Day(); day++ {
				f := 0.6 + 0.7*simHash(seed, v.D.MAC, "day", int64(day))
				rx += float64(v.D.RxBps) * mean * 86400 * f
				tx += float64(v.D.TxBps) * mean * 86400 * f
			}
		}
		devs[v.D.MAC] = map[string]interface{}{"rx": uint64(rx), "tx": uint64(tx), "sim": true}
	}
	cp := make(map[string]interface{}, len(out)+1)
	for k, val := range out {
		cp[k] = val
	}
	cp["devices"] = devs
	return cp
}

// simMergeOnlineHours /api/online_hours: 在线的模拟设备今天记 (当前小时+1) 小时
func (s *server) simMergeOnlineHours(h map[string]map[string]int) map[string]map[string]int {
	now := time.Now()
	views, _ := s.simViews(now)
	day := now.Format("20060102")
	for i := range views {
		if views[i].D.Offline {
			continue
		}
		if h == nil {
			h = map[string]map[string]int{}
		}
		h[views[i].D.MAC] = map[string]int{day: now.Hour() + 1}
	}
	return h
}

// simMergeAppLimits /api/app_limits: 追加模拟设备的按应用限速
func (s *server) simMergeAppLimits(items []AppLimitItem) []AppLimitItem {
	if !s.simActive() {
		return items
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.f.Devices {
		ids := make([]string, 0, len(d.AppLimits))
		for id := range d.AppLimits {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			items = append(items, AppLimitItem{MAC: d.MAC, AppID: id, DownMbps: d.AppLimits[id]})
		}
	}
	return items
}

// simMergeDPIState /api/dpi_state: state.clients 追加模拟客户端(只在 dpid 状态存在时)
func (s *server) simMergeDPIState(raw interface{}) interface{} {
	root, ok := raw.(map[string]interface{})
	if !ok {
		return raw
	}
	now := time.Now()
	views, seed := s.simViews(now)
	if len(views) == 0 {
		return raw
	}
	clients, _ := root["clients"].(map[string]interface{})
	if clients == nil {
		clients = map[string]interface{}{}
		root["clients"] = clients
	}
	lib := func(id string) (simApp, bool) { return simFindApp(s.hncDir, id) }
	for i := range views {
		v := &views[i]
		d := &v.D
		last := now.Unix()
		if d.Offline {
			last -= 600
		}
		var hosts []map[string]interface{}
		lastSNI := ""
		for _, c := range simConnsFor(v, seed, lib) {
			cnt := int(math.Max(1, c.weight*200))
			hosts = append(hosts, map[string]interface{}{"name": c.host, "count": cnt, "last_seen": last})
			if lastSNI == "" && c.nameSrc == "sni" {
				lastSNI = c.host
			}
		}
		cl := map[string]interface{}{
			"client_ip": d.IP, "client_mac": d.MAC, "client_ips": []string{d.IP},
			"first_seen": d.Created, "last_seen": last,
			"dns_events": 40 + len(hosts)*12, "tls_events": 25 + len(hosts)*9,
			"last_hostname": d.Hostname, "last_sni": lastSNI,
			"top_hostnames": hosts, "top_sni": hosts,
			"rx_bytes": v.Down, "tx_bytes": v.Up, "sim": true,
		}
		if d.AppID != "" {
			id, name, cat := simAppIDName(d)
			cl["top_apps"] = []map[string]interface{}{{"id": id, "name": name, "category": cat,
				"count": 30 + len(hosts)*5, "last_seen": last, "confidence": "high", "bytes": v.Down + v.Up}}
		}
		clients["sim-"+d.MAC] = cl
	}
	return raw
}
