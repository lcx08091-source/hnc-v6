// app_usage.go — v5.16 按应用的真实流量统计
//
// 为什么: dpid 的每应用字节数只来自它抓到的包 —— cBPF 只放行 DNS 与 TLS/QUIC
// 握手, 视频/下载的数据包根本不经过它, 所以"按应用流量"严重偏小(只有握手那点)。
// 真实字节在内核连接表(conntrack, nf_conntrack_acct=1)里: 每条连接都有双向
// 累计字节。这里后台每 10 秒读一次连接表, 按连接做字节差分, 按
// (设备, 应用, 小时) 累加 —— 和 iptables 全量统计同一个 netfilter 口径, 能对得上。
//
// 应用归属: 同 /api/connections —— ip_app_map(规则命中)优先, 否则 DNS/SNI
// 反查表归类(DNS 关联); 都没有记为「未识别」, 目的是局域网的记为「局域网」。
// 误差: 两次采样之间开始又结束的短连接会漏掉(通常 < 1%); 连接结束前最后
// 不到 10 秒的字节会丢。
//
// 存储: run/app_usage.YYYYMMDD.json(本地日期), 每分钟落盘一次(有变化才写),
// 保留 32 天。
//
//   GET /api/app_usage?days=1|3|7|30&mac=<可选>
//     → {total_up, total_down, by_app:[{id,name,category,up,down}], by_hour:[{h,up,down}],
//        by_device:[{mac,up,down}], days, since, acct}

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	appUsageEvery    = 10 * time.Second
	appUsageFlush    = 60 * time.Second
	appUsageKeepDays = 32
	appUnknownID     = "_unknown"
	appLocalID       = "_local"
)

// 一天的累计: hour(0-23) → "mac|app" → [up, down]
type appUsageDay struct {
	Date  string                          `json:"date"` // YYYYMMDD(本地)
	Hours map[string]map[string][2]uint64 `json:"hours"`
	Apps  map[string]appUsageMeta         `json:"apps"`
}

type appUsageMeta struct {
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
}

var appUsage struct {
	mu    sync.Mutex
	day   *appUsageDay
	dirty bool
	prev  map[string][2]uint64 // 连接 key → 上次看到的 [up, down] 累计
	init  bool
}

func appUsagePath(hncDir, date string) string {
	return filepath.Join(hncDir, "run", "app_usage."+date+".json")
}

func loadAppUsageDay(hncDir, date string) *appUsageDay {
	d := &appUsageDay{Date: date, Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
	if b, err := os.ReadFile(appUsagePath(hncDir, date)); err == nil {
		var x appUsageDay
		if json.Unmarshal(b, &x) == nil && x.Hours != nil {
			if x.Apps == nil {
				x.Apps = map[string]appUsageMeta{}
			}
			x.Date = date
			return &x
		}
	}
	return d
}

// appUsageTick 读一次连接表, 把新增字节记到当天。返回本轮记入的字节数(测试用)。
func (s *server) appUsageTick(now time.Time) uint64 {
	sn := conntrackSnapshot()
	if !sn.readable {
		return 0
	}
	owner := map[string]string{}
	for mac, ips := range s.deviceIPsByMAC() {
		for _, ip := range ips {
			owner[ip] = mac
		}
	}
	names := s.loadIPNames()
	apps := s.loadIPApps()

	appUsage.mu.Lock()
	defer appUsage.mu.Unlock()
	date := now.Format("20060102")
	if appUsage.day == nil || appUsage.day.Date != date {
		if appUsage.day != nil && appUsage.dirty {
			_ = saveAppUsageDay(s.hncDir, appUsage.day)
		}
		appUsage.day = loadAppUsageDay(s.hncDir, date)
		appUsage.dirty = false
	}
	first := !appUsage.init
	next := make(map[string][2]uint64, len(sn.entries))
	hour := strconv.Itoa(now.Hour())
	var added uint64
	for _, e := range sn.entries {
		mac, ok := owner[e.Src]
		if !ok {
			continue
		}
		k := e.key()
		cur := [2]uint64{e.UpB, e.DnB}
		next[k] = cur
		var du, dd uint64
		if p, seen := appUsage.prev[k]; seen {
			if cur[0] >= p[0] {
				du = cur[0] - p[0]
			}
			if cur[1] >= p[1] {
				dd = cur[1] - p[1]
			}
		} else if !first {
			// 两次采样之间新建的连接: 它的全部字节都发生在这段时间里
			du, dd = cur[0], cur[1]
		}
		if du == 0 && dd == 0 {
			continue
		}
		id, meta := appUnknownID, appUsageMeta{Name: "未识别"}
		if e.Dst != "" && (isPrivateIP(e.Dst) || owner[e.Dst] != "") {
			id, meta = appLocalID, appUsageMeta{Name: "局域网"}
		} else if a, ok := appForIP(e.Dst, apps, names); ok {
			id, meta = a.ID, appUsageMeta{Name: a.Name, Category: a.Category}
		}
		d := appUsage.day
		if d.Hours[hour] == nil {
			d.Hours[hour] = map[string][2]uint64{}
		}
		mk := mac + "|" + id
		v := d.Hours[hour][mk]
		v[0] += du
		v[1] += dd
		d.Hours[hour][mk] = v
		if old, ok := d.Apps[id]; !ok || old.Name != meta.Name || old.Category != meta.Category {
			d.Apps[id] = meta
		}
		appUsage.dirty = true
		added += du + dd
	}
	appUsage.prev = next
	appUsage.init = true
	return added
}

func saveAppUsageDay(hncDir string, d *appUsageDay) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(appUsagePath(hncDir, d.Date), b)
}

func (s *server) appUsageFlush(now time.Time) {
	appUsage.mu.Lock()
	var d *appUsageDay
	if appUsage.dirty && appUsage.day != nil {
		b, _ := json.Marshal(appUsage.day)
		d = &appUsageDay{}
		_ = json.Unmarshal(b, d)
		appUsage.dirty = false
	}
	appUsage.mu.Unlock()
	if d != nil {
		if err := saveAppUsageDay(s.hncDir, d); err != nil {
			appUsage.mu.Lock()
			appUsage.dirty = true
			appUsage.mu.Unlock()
		}
	}
	// 清理 32 天前的文件
	ents, _ := os.ReadDir(filepath.Join(s.hncDir, "run"))
	cut := now.AddDate(0, 0, -appUsageKeepDays).Format("20060102")
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "app_usage.") && strings.HasSuffix(n, ".json") {
			if date := strings.TrimSuffix(strings.TrimPrefix(n, "app_usage."), ".json"); len(date) == 8 && date < cut {
				_ = os.Remove(filepath.Join(s.hncDir, "run", n))
			}
		}
	}
}

// AppUsageLoop 后台采样(10s)与落盘(60s)
func (s *server) AppUsageLoop(stop <-chan struct{}) {
	tk := time.NewTicker(appUsageEvery)
	defer tk.Stop()
	lastFlush := time.Now()
	for {
		select {
		case <-stop:
			s.appUsageFlush(time.Now())
			return
		case now := <-tk.C:
			s.appUsageTick(now)
			s.connBlockRefresh() // v5.16: 域名封锁跟随反查表更新 IP
			if now.Sub(lastFlush) >= appUsageFlush {
				s.appUsageFlush(now)
				lastFlush = now
			}
		}
	}
}

// ─── 查询 ─────────────────────────────────────────────────────────────

func (s *server) apiAppUsage(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 1
	}
	if days > 31 {
		days = 31
	}
	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
	if mac != "" && !validMAC(mac) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	now := time.Now()
	type acc struct{ up, dn uint64 }
	byApp := map[string]*acc{}
	byDev := map[string]*acc{}
	var byHour [24]acc
	meta := map[string]appUsageMeta{}
	var totUp, totDn uint64
	since := ""
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("20060102")
		var d *appUsageDay
		appUsage.mu.Lock()
		if appUsage.day != nil && appUsage.day.Date == date {
			b, _ := json.Marshal(appUsage.day)
			d = &appUsageDay{}
			_ = json.Unmarshal(b, d)
		}
		appUsage.mu.Unlock()
		if d == nil {
			if _, err := os.Stat(appUsagePath(s.hncDir, date)); err != nil {
				continue
			}
			d = loadAppUsageDay(s.hncDir, date)
		}
		if since == "" {
			since = date
		}
		for id, m := range d.Apps {
			meta[id] = m
		}
		for h, cells := range d.Hours {
			hi, _ := strconv.Atoi(h)
			for mk, v := range cells {
				sep := strings.IndexByte(mk, '|')
				if sep < 0 {
					continue
				}
				m, id := mk[:sep], mk[sep+1:]
				if mac != "" && m != mac {
					continue
				}
				if byApp[id] == nil {
					byApp[id] = &acc{}
				}
				byApp[id].up += v[0]
				byApp[id].dn += v[1]
				if byDev[m] == nil {
					byDev[m] = &acc{}
				}
				byDev[m].up += v[0]
				byDev[m].dn += v[1]
				if hi >= 0 && hi < 24 {
					byHour[hi].up += v[0]
					byHour[hi].dn += v[1]
				}
				totUp += v[0]
				totDn += v[1]
			}
		}
	}
	apps := make([]map[string]interface{}, 0, len(byApp))
	for id, a := range byApp {
		m := meta[id]
		name := m.Name
		if name == "" {
			name = id
		}
		apps = append(apps, map[string]interface{}{"id": id, "name": name, "category": m.Category,
			"up": a.up, "down": a.dn, "sdk": appTier(m.Category) == tierHidden})
	}
	sort.Slice(apps, func(i, j int) bool {
		ti := apps[i]["up"].(uint64) + apps[i]["down"].(uint64)
		tj := apps[j]["up"].(uint64) + apps[j]["down"].(uint64)
		if ti != tj {
			return ti > tj
		}
		return fmt.Sprint(apps[i]["id"]) < fmt.Sprint(apps[j]["id"])
	})
	devs := make([]map[string]interface{}, 0, len(byDev))
	for m, a := range byDev {
		devs = append(devs, map[string]interface{}{"mac": m, "up": a.up, "down": a.dn})
	}
	sort.Slice(devs, func(i, j int) bool {
		return devs[i]["up"].(uint64)+devs[i]["down"].(uint64) > devs[j]["up"].(uint64)+devs[j]["down"].(uint64)
	})
	hours := make([]map[string]interface{}, 24)
	for h := 0; h < 24; h++ {
		hours[h] = map[string]interface{}{"h": h, "up": byHour[h].up, "down": byHour[h].dn}
	}
	sn := conntrackSnapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "days": days, "mac": mac, "since": since,
		"total_up": totUp, "total_down": totDn,
		"by_app": apps, "by_device": devs, "by_hour": hours,
		"readable": sn.readable, "acct": sn.acct,
	})
}
