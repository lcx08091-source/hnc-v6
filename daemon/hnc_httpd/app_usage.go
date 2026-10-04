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
// 精确模式(v5.18, ct_events.go): 订阅 conntrack DESTROY 事件拿连接最终字节,
// 补上「两次采样之间开始又结束的短连接」和「连接结束前最后不到 10 秒」这两块。
// 订阅失败(权限/内核)时退回纯轮询, 那两类误差仍在(通常 < 1%)。API 带 precise。
//
// 存储: run/app_usage.YYYYMMDD.json(本地日期), 每分钟落盘一次(有变化才写),
// 保留 32 天。
//
//   GET /api/app_usage?days=1|3|7|30&mac=<可选>
//     → {total_up, total_down, by_app:[{id,name,category,up,down}], by_hour:[{h,up,down}],
//        by_device:[{mac,up,down}], days, since, acct, precise}

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
	// v6.x 使用时长(app_time.go): hour → "mac|app" → 活跃秒数; "mac|app" → [首次, 最近] 活跃 unix。
	// 旧文件没有这些字段 → 解出来是 nil, 记账时按需创建(向后兼容)。
	Active map[string]map[string]uint32 `json:"active,omitempty"`
	Seen   map[string][2]int64          `json:"seen,omitempty"`
	// 未识别流量按目的(基础域名 / IP)聚合, 条数有上限(appUnknownMax)
	Unknown map[string]*appUnknownAgg `json:"unknown,omitempty"`
	// v5.21 共现推断(traffic_ident.go): "mac|app" → [up, down], 是 Hours 里该应用字节的子集
	Inferred map[string][2]uint64 `json:"inferred,omitempty"`
	// v6.x DPI v2(fp_learn.go): 按指纹(fp/seed)与用户纠正(user)归属的字节, "mac|app" → [up, down],
	// 都是 Hours 的子集; FPW = Σ 字节×置信度(/api/app_usage 用它算平均置信度)
	FP   map[string][2]uint64 `json:"fp,omitempty"`
	FPW  map[string]float64   `json:"fp_w,omitempty"`
	User map[string][2]uint64 `json:"user,omitempty"`
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
	guard clockGuard // v5.20: 时钟不可信/跳变检测(clock_guard.go)
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
	fpSt := fpFor(s.hncDir)
	fresh := fpSt.tick(now, names) // v6.x DPI v2: 用户纠正规则 + 摄入 dpi_flows.json(指纹学习), 在 appUsage.mu 外做 I/O
	// v5.27 T3 启动指纹(影子运行, 只产出启动事件): 新的 ClientHello 交给识别; 学习最多 30 分钟一次,
	// 只在本机抓包开着时做。都在 appUsage.mu / fpSt.mu 之外。
	sfp := startupFor(s.hncDir)
	sfp.observe(fresh, now)
	sfp.maybeLearn(now)

	appUsage.mu.Lock()
	defer appUsage.mu.Unlock()
	// v5.20: 时钟不可信 → 整轮跳过(不消费连接表差分, 不写错日文件);
	// 跳变 → 重建基线(丢弃跨跳变的差分与积压事件), 不把一大坨字节记进一个桶/错的天。
	appUsage.guard.name = "app_usage"
	switch appUsage.guard.step(s.hncDir, now) {
	case clockInsane:
		return 0
	case clockJump:
		_, _, _ = ctEventsDrain()
		_, _ = ctNewDrain()
		identReset() // v5.21: 窗口/暂缓/推测缓存都按时间算, 跳变后重来
		fgSt.reset(now)
		flowShapeReset() // DPI v2: 流形态窗口按时间算, 跳变后重来(flow_shape.go)
		appUsage.init = false
		appUsageAcctStep(&appUsage.prev, &appUsage.init, sn.entries, sn.at, nil, func(src string) bool { _, ok := owner[src]; return ok })
		appTimeLastTick = time.Time{}
		return 0
	}
	date := now.Format("20060102")
	if appUsage.day == nil || appUsage.day.Date != date {
		if appUsage.day != nil && appUsage.dirty {
			_ = saveAppUsageDay(s.hncDir, appUsage.day)
		}
		appUsage.day = loadAppUsageDay(s.hncDir, date)
		appUsage.dirty = false
	}
	events, _, _ := ctEventsDrain()
	keep := func(src string) bool { _, ok := owner[src]; return ok }
	// v5.21: 上一轮快照的连接(判「本轮新出现」); acct step 会从旧 map 里删掉有销毁事件的 key, 先记下
	prevKeys := appUsage.prev
	oldEv := map[string]bool{}
	for _, ev := range events {
		if _, ok := prevKeys[ev.Key]; ok {
			oldEv[ev.Key] = true
		}
	}
	deltas := appUsageAcctStep(&appUsage.prev, &appUsage.init, sn.entries, sn.at, events, keep)
	newStarts, _ := ctNewDrain()
	isNew := func(k string) bool { _, ok := prevKeys[k]; return !ok && !oldEv[k] }
	ix := identSt.observe(now, deltas, newStarts, isNew, owner, apps, names)
	// v6.x DPI v2: 指纹/用户纠正归属(fp_learn.go)
	ix.fp = fpSt
	flowShapeTick(sn.at, sn, events, owner, apps, names) // DPI v2: 流形态分类(flow_shape.go)
	added := appUsageRecordIdent(appUsage.day, deltas, owner, apps, names, now, appTimeTickSec(now), ix)
	if len(deltas) > 0 {
		appUsage.dirty = true
	}
	return added
}

// appUsageRecord 把一轮差分记到当天(调用方持 appUsage.mu; 无 I/O, 单测直接喂)。
// 字节按 (设备, 应用, 小时) 累加; 同时把本轮每个 (设备, 应用) 的字节交给
// appTimeStep 记使用时长, 未识别的目的交给 appUnknownAdd 聚合。
func appUsageRecord(d *appUsageDay, deltas []appUsageDelta, owner map[string]string,
	apps map[string]ipApp, names map[string]ipName, now time.Time, tickSec int) uint64 {
	return appUsageRecordIdent(d, deltas, owner, apps, names, now, tickSec, nil)
}

// appUsageRecordIdent v5.21: 同 appUsageRecord, ix 非 nil 时叠加 traffic_ident.go 的
// 隧道归属(_tunnel)、共现推断(记 d.Inferred)与新连接暂缓(ix.released 在本轮补记)。
func appUsageRecordIdent(d *appUsageDay, deltas []appUsageDelta, owner map[string]string,
	apps map[string]ipApp, names map[string]ipName, now time.Time, tickSec int, ix *identCtx) uint64 {
	hour := strconv.Itoa(now.Hour())
	var added uint64
	tick := map[string]uint64{}
	cats := map[string]string{}
	var fobs []fgObs // DPI v2 前台模型(fg_model.go)的输入: 已定归属的差分
	if ix != nil && len(ix.released) > 0 {
		deltas = append(append([]appUsageDelta(nil), ix.released...), deltas...)
		ix.released = nil
	}
	for _, dl := range deltas {
		mac := owner[dl.Src]
		id, meta := appUnknownID, appUsageMeta{Name: "未识别"}
		inferred := false
		attrSrc, attrConf := "", 0.0 // v6.x DPI v2: "fp"/"seed"/"user" 单独计数
		if dl.Dst != "" && (isPrivateIP(dl.Dst) || owner[dl.Dst] != "") {
			id, meta = appLocalID, appUsageMeta{Name: "局域网"}
		} else if ix.hold(dl) {
			continue // 新连接等共现窗口合上, 下一轮随 ix.released 补记
		} else if fa, ok := ix.fpClassify(dl); ok { // 用户纠正 > 规则库 > 指纹 > 共现/隧道启发式(fp_learn.go)
			id, meta, attrSrc, attrConf = fa.App.ID, appUsageMeta{Name: fa.App.Name, Category: fa.App.Category}, fa.Src, fa.Conf
		} else if xid, xm, xinf, ok := ix.classify(dl, mac); ok {
			id, meta, inferred = xid, xm, xinf
		} else if a, src, ok := appForIPSrc(dl.Dst, apps, names); ok {
			id, meta = a.ID, appUsageMeta{Name: a.Name, Category: a.Category}
			if src == "user" {
				attrSrc = "user"
			}
		}
		// DPI v2(ip_owner.go): 以上都没归上、且目的 IP 没有反查名 → 按 IP 归属库归到
		// 「XX系(未细分)」伪应用(只限消费级应用运营方; 云/CDN/运营商仍记未识别)。优先级最低。
		if id == appUnknownID && dl.Dst != "" && names[dl.Dst].Name == "" {
			if a, ok := orgAppForIP(dl.Dst); ok {
				id, meta = a.ID, appUsageMeta{Name: a.Name, Category: a.Category}
			}
		}
		if d.Hours[hour] == nil {
			d.Hours[hour] = map[string][2]uint64{}
		}
		mk := mac + "|" + id
		v := d.Hours[hour][mk]
		v[0] += dl.Up
		v[1] += dl.Dn
		d.Hours[hour][mk] = v
		if inferred {
			if d.Inferred == nil {
				d.Inferred = map[string][2]uint64{}
			}
			iv := d.Inferred[mk]
			iv[0] += dl.Up
			iv[1] += dl.Dn
			d.Inferred[mk] = iv
		}
		appUsageAddSrc(d, mk, attrSrc, attrConf, dl.Up, dl.Dn)
		if old, ok := d.Apps[id]; !ok || old.Name != meta.Name || old.Category != meta.Category {
			d.Apps[id] = meta
		}
		added += dl.Up + dl.Dn
		tick[mk] += dl.Up + dl.Dn
		cats[id] = meta.Category
		if id == appUnknownID && dl.Dst != "" {
			appUnknownAdd(d, dl.Dst, names[dl.Dst].Name, mac, dl.Up+dl.Dn)
		}
		if ix != nil && mac != "" && id != appUnknownID && id != appLocalID {
			fobs = append(fobs, fgObs{MAC: mac, ID: id, Name: meta.Name, Category: meta.Category, Key: dl.Key, Up: dl.Up, Dn: dl.Dn, Inferred: inferred})
		}
	}
	appTimeStep(d, tick, cats, now, tickSec)
	if ix != nil { // 只在真实采样路径(appUsageTick)上推进前台模型
		fgSt.step(now, fobs, "")
	}
	return added
}

// appUsageDelta 一条连接本轮新增的字节
type appUsageDelta struct {
	Src, Dst string
	Up, Dn   uint64
	Key      string // v5.21: 连接五元组 key(ctEntry.key() 格式), 给 VPN 识别/共现推断用; 单测可留空
}

func satSub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return 0
}

// appUsageAcctStep 纯记账逻辑(无 I/O, 单测直接喂数据)。
//
//	prev:   上一轮快照里各连接的 [up, down] 累计(只含 keep 的连接), 本函数会替换它
//	init:   是否已建立基线; 第一轮只建基线, 历史字节与此前缓冲的事件都不算
//	entries/snapAt: 本轮 /proc 快照及其开始读取的时间
//	events: 自上一轮以来收到的 DESTROY 事件(带最终字节)
//
// 规则(保证不重复计数):
//  1. 事件的 key 在 prev 里 → 记「最终 − 上次快照」(连接的尾巴), 并从 prev 删掉;
//     不在 prev 里 → 这条连接从没被快照看到过, 记它的全部字节。
//  2. 本轮快照里某 key 有销毁事件且事件晚于快照开始时间 → 快照里这条是已死连接
//     的旧读数(字节已由事件记完), 跳过、也不进新 prev; 事件早于快照 → 同五元组
//     新建的连接, 按新连接处理(prev 已被规则 1 删掉 → 记全部字节)。
//  3. 其余照旧: 在 prev 里记差分(计数器变小按 0), 不在 prev 里(非首轮)记全部。
func appUsageAcctStep(prev *map[string][2]uint64, init *bool, entries []ctEntry, snapAt time.Time,
	events []ctDestroy, keep func(src string) bool) []appUsageDelta {
	next := make(map[string][2]uint64, len(entries))
	if !*init {
		for i := range entries {
			e := &entries[i]
			if keep(e.Src) {
				next[e.key()] = [2]uint64{e.UpB, e.DnB}
			}
		}
		*prev, *init = next, true
		return nil
	}
	if *prev == nil {
		*prev = map[string][2]uint64{}
	}
	var out []appUsageDelta
	dead := map[string]time.Time{}
	for _, ev := range events {
		if !ev.HasCnt || !keep(ev.Src) {
			continue
		}
		if t, ok := dead[ev.Key]; !ok || ev.At.After(t) {
			dead[ev.Key] = ev.At
		}
		du, dd := ev.UpB, ev.DnB
		if p, ok := (*prev)[ev.Key]; ok {
			du, dd = satSub(ev.UpB, p[0]), satSub(ev.DnB, p[1])
			delete(*prev, ev.Key)
		}
		if du != 0 || dd != 0 {
			out = append(out, appUsageDelta{Src: ev.Src, Dst: ev.Dst, Up: du, Dn: dd, Key: ev.Key})
		}
	}
	for i := range entries {
		e := &entries[i]
		if !keep(e.Src) {
			continue
		}
		k := e.key()
		if t, ok := dead[k]; ok && t.After(snapAt) {
			continue // 旧读数, 连接已由事件结清
		}
		cur := [2]uint64{e.UpB, e.DnB}
		next[k] = cur
		du, dd := cur[0], cur[1] // 两次采样之间新建的连接: 全部字节都发生在这段时间里
		if p, seen := (*prev)[k]; seen {
			du, dd = satSub(cur[0], p[0]), satSub(cur[1], p[1])
		}
		if du != 0 || dd != 0 {
			out = append(out, appUsageDelta{Src: e.Src, Dst: e.Dst, Up: du, Dn: dd, Key: k})
		}
	}
	*prev = next
	return out
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
	fgSt.flush(now) // DPI v2: 前台时间线落盘 + 清理(fg_model.go; 未 load 过时不写)
	if d != nil {
		if err := saveAppUsageDay(s.hncDir, d); err != nil {
			appUsage.mu.Lock()
			appUsage.dirty = true
			appUsage.mu.Unlock()
		}
	}
	// 清理 32 天前的文件(v5.20: 时钟不可信时不清, 防跑到未来的时钟把历史全删)
	if !clockSane(s.hncDir, now) {
		return
	}
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

// AppUsageLoop 后台采样(基准 10s, v5.22 按活动状态自适应, 见 power_sched.go)与落盘(60s)
func (s *server) AppUsageLoop(stop <-chan struct{}) {
	last := time.Now()
	lastFlush := last
	fgSt.load(s.hncDir, last) // DPI v2: 载入今天已有的前台时间线
	for {
		if !powerWait(stop, "app_usage", last, s.appUsageFlags) {
			s.appUsageFlush(time.Now())
			return
		}
		now := time.Now()
		appTimeSetCapFor(powerCurrent("app_usage"))
		// 从慢档(>40s)回来的第一轮: 时长按基准 10s 记, 不把整段空闲算成「在用」
		if now.Sub(last) > 2*appTimeMaxTickSec*time.Second {
			appTimeResetLast()
		}
		last = now
		s.appUsageTick(now)
		s.appTimeEnforce(now) // v6.x: 应用时长上限 → 告警(封锁由下一行的派生封锁项落地)
		s.connBlockRefresh()  // v5.16: 域名封锁跟随反查表更新 IP
		if now.Sub(lastFlush) >= appUsageFlush {
			s.appUsageFlush(now)
			lastFlush = now
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
	resolve := macAliasResolver(s.hncDir) // v5.21: 合并过的旧 MAC 历史归到新 MAC
	if mac != "" {
		mac = resolve(mac)
	}
	now := time.Now()
	type acc struct{ up, dn uint64 }
	byApp := map[string]*acc{}
	byDev := map[string]*acc{}
	var byHour [24]acc
	meta := map[string]appUsageMeta{}
	activeByApp := map[string]uint64{}
	inferredByApp := map[string]uint64{} // v5.21 共现推断的字节
	var totUp, totDn, totInferred uint64
	srcAgg := newAppUsageSrcAgg() // v6.x DPI v2: 指纹/用户纠正字节(fp_learn.go)
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
			if _, err := os.Stat(appUsagePath(s.hncDir, date)); err == nil {
				d = loadAppUsageDay(s.hncDir, date)
			}
		}
		d = s.simMergeAppUsageDay(d, date) // 模拟环境: 今天叠加模拟设备; 关闭时原样
		if d == nil {
			continue
		}
		if since == "" {
			since = date
		}
		for id, m := range d.Apps {
			meta[id] = m
		}
		srcAgg.addDay(d, mac, resolve)
		for mk, v := range d.Inferred {
			sep := strings.IndexByte(mk, '|')
			if sep < 0 || (mac != "" && mk[:sep] != mac) {
				continue
			}
			inferredByApp[mk[sep+1:]] += v[0] + v[1]
			totInferred += v[0] + v[1]
		}
		for _, cells := range d.Active { // v6.x 使用时长
			for mk, sec := range cells {
				sep := strings.IndexByte(mk, '|')
				if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac) {
					continue
				}
				activeByApp[mk[sep+1:]] += uint64(sec)
			}
		}
		for h, cells := range d.Hours {
			hi, _ := strconv.Atoi(h)
			for mk, v := range cells {
				sep := strings.IndexByte(mk, '|')
				if sep < 0 {
					continue
				}
				m, id := resolve(mk[:sep]), mk[sep+1:]
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
		apps = append(apps, srcAgg.annotate(id, map[string]interface{}{"id": id, "name": name, "category": m.Category,
			"up": a.up, "down": a.dn, "sdk": appTier(m.Category) == tierHidden,
			"active_sec": activeByApp[id], "inferred_bytes": inferredByApp[id]}))
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
		// v5.21: inferred_bytes = 其中按共现推断归到应用的字节(界面标「推测」)
		"by_app": apps, "by_device": devs, "by_hour": hours, "inferred_bytes": totInferred,
		"readable": sn.readable, "acct": sn.acct,
		// v6.x DPI v2: fp_bytes = 按学习指纹归属的字节(界面标「指纹识别」), user_bytes = 按用户纠正归属的字节
		"fp_bytes": srcAgg.totFP, "user_bytes": srcAgg.totUser,
		// v5.18: true = conntrack DESTROY 事件订阅在线(短连接/连接尾巴也计入)
		"precise": sn.acct && ctEventsPrecise(),
	})
}
