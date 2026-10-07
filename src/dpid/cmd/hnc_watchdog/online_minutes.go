// online_minutes.go — v5.30 T1a: 在线时长按分钟累计。
//
// 旧做法(v5.25 起): 热点开着时每 ~55 分钟采样一次, 此刻在线的设备各写一行
// {"t","day","mac"}, httpd 一行算 1 小时 → 刚连上 5 分钟、正好赶上采样的
// 设备显示「今日在线 1 小时」(用户截图实锤)。
//
// 新做法:
//   - 每 onlineSampleEvery(5 分钟)采样一次(进程内读 devices.json, 不起 sh;
//     只在 handleActive 确认热点开着时调用), 在内存里按 (day, mac) 累加分钟;
//     本次记的分钟数 = 距上次采样的间隔(上限 onlineCreditMaxMin, 首次 5 分钟),
//     Doze 把主循环拉长到 3 分钟一轮时不会少记; 跨零点的间隔按零点拆到两天。
//   - 每 onlineFlushEvery(~55 分钟)或跨日时落盘, 一台设备一行
//     {"t","day","mac","m":<分钟>} —— 文件增长与旧版同量级。
//   - 看门狗收到 SIGTERM 正常退出时(main → onExit)把未落盘的分钟写掉。
//
// 读侧(httpd onlineMinutesByMAC): 有 m 按 m 算, 旧行没有 m 按 60 算。
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"time"
)

const (
	// onlineSampleEvery 采样间隔; 单次采样(且是本进程第一次)记这么多分钟。
	onlineSampleEvery = 5 * time.Minute
	// onlineFlushEvery 落盘间隔(与旧版 3300 秒采样同节拍 → 文件行数同量级)。
	onlineFlushEvery = 3300 * time.Second
	// onlineCreditMaxMin 单次采样最多记的分钟数。两次采样间隔被拉长(热点关过、
	// 进程被冻结)时不把整段空档都算成在线。
	onlineCreditMaxMin = 10
)

type onlineKey struct{ day, mac string }

// onlineAccum 在线分钟累加器。只在主循环 goroutine 串行使用(onExit 在主循环
// 返回之后调用), 不需要锁。
type onlineAccum struct {
	file    string                // run/online_hours.jsonl
	devices string                // data/devices.json
	clockOK func(time.Time) bool  // 时钟可信才采样(否则 day 会是 1970 之类)
	pending map[onlineKey]int     // 还没落盘的分钟
	last    time.Time             // 上次采样
	flushed time.Time             // 上次落盘(首次采样时置为采样时刻)
	failLog func(string, ...any)  // 落盘失败记日志
	readDev func() ([]byte, bool) // 读 devices.json(测试可替换)
}

func newOnlineAccum(file, devices string) *onlineAccum {
	a := &onlineAccum{
		file:    file,
		devices: devices,
		clockOK: clockSaneNow,
		pending: map[onlineKey]int{},
		failLog: logf,
	}
	a.readDev = func() ([]byte, bool) {
		b, err := os.ReadFile(a.devices)
		if err != nil || len(b) > 8<<20 {
			return nil, false
		}
		return b, true
	}
	return a
}

// onlineAcc 生产实例; budget_test / online_minutes_test 换成临时目录里的实例。
var onlineAcc = newOnlineAccum(onlineHoursFile, dataDir+"/devices.json")

// roundMin 时长 → 分钟(四舍五入)。
func roundMin(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + 30*time.Second) / time.Minute)
}

// creditSplit 本次采样该记的分钟, 按日拆分: 区间 [now-credit, now] 跨零点时
// 零点前的部分记到前一天。返回 day → 分钟。
func creditSplit(now time.Time, credit time.Duration) map[string]int {
	total := roundMin(credit)
	out := map[string]int{}
	if total <= 0 {
		return out
	}
	from := now.Add(-credit)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if from.Before(midnight) {
		before := roundMin(midnight.Sub(from))
		if before > total {
			before = total
		}
		if before > 0 {
			out[from.Format("20060102")] += before
		}
		total -= before
	}
	if total > 0 {
		out[now.Format("20060102")] += total
	}
	return out
}

// sample 到点(距上次 ≥ onlineSampleEvery)则采样一次; 顺带判断该不该落盘。
func (a *onlineAccum) sample(now time.Time) {
	since := now.Sub(a.last)
	if !a.last.IsZero() && since >= 0 && since < onlineSampleEvery {
		return
	}
	if !a.clockOK(now) {
		return
	}
	credit := onlineSampleEvery
	if !a.last.IsZero() && since > 0 {
		credit = since
	}
	if max := time.Duration(onlineCreditMaxMin) * time.Minute; credit > max {
		credit = max
	}
	a.last = now
	if a.flushed.IsZero() {
		a.flushed = now
	}
	if b, ok := a.readDev(); ok {
		if macs := onlineMACs(b, now.Unix()); len(macs) > 0 {
			split := creditSplit(now, credit)
			for _, mac := range macs {
				for day, m := range split {
					a.pending[onlineKey{day, mac}] += m
				}
			}
		}
	}
	if a.flushDue(now) {
		a.flush(now)
	}
}

// flushDue 距上次落盘 ≥ onlineFlushEvery, 或累加器里有不是今天的分钟(跨日)。
func (a *onlineAccum) flushDue(now time.Time) bool {
	if len(a.pending) == 0 {
		return false
	}
	if now.Sub(a.flushed) >= onlineFlushEvery || now.Sub(a.flushed) < 0 {
		return true
	}
	today := now.Format("20060102")
	for k := range a.pending {
		if k.day != today {
			return true
		}
	}
	return false
}

// flush 把累加的分钟追加写进 online_hours.jsonl(一台设备一天一行), 清空累加器。
// 写失败时保留累加器, 下次再试。
func (a *onlineAccum) flush(now time.Time) {
	a.flushed = now
	if len(a.pending) == 0 {
		return
	}
	keys := make([]onlineKey, 0, len(a.pending))
	for k, m := range a.pending {
		if m > 0 {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].day != keys[j].day {
			return keys[i].day < keys[j].day
		}
		return keys[i].mac < keys[j].mac
	})
	var buf bytes.Buffer
	for _, k := range keys {
		fmt.Fprintf(&buf, "{\"t\":%d,\"day\":\"%s\",\"mac\":\"%s\",\"m\":%d}\n", now.Unix(), k.day, k.mac, a.pending[k])
	}
	f, err := os.OpenFile(a.file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		a.failLog("online minutes flush: %v", err)
		return
	}
	_, werr := f.Write(buf.Bytes())
	cerr := f.Close()
	if werr != nil || cerr != nil {
		a.failLog("online minutes flush: write=%v close=%v", werr, cerr)
		return
	}
	a.pending = map[onlineKey]int{}
}

// onExit 看门狗正常退出(SIGTERM → mainLoop 返回)时调用: 未落盘的分钟写掉。
func onExit() {
	onlineAcc.flush(nowFn())
}
