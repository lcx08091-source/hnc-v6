// power_hooks.go — v5.22 功耗: 各循环接入自适应间隔时需要的小钩子。
package main

import (
	"sync/atomic"
	"time"
)

// appUsageFlags app_usage 循环的额外策略输入:
//   - CtPrecise: conntrack DESTROY 事件在用 → 短连接字节由事件补齐, 放慢轮询不丢数
//   - Enforcing: 配了应用时长上限 / 类别封锁 / 连接封锁 → 本循环承担执法(时长判定、
//     域名封锁跟随 DNS 换 IP), 有客户端时绝不放慢
func (s *server) appUsageFlags() loopFlags {
	ctl := loadAppControls(s.hncDir)
	enf := len(ctl.TimeLimits) > 0 || len(ctl.CategoryBlocks) > 0 || len(readConnBlocks(s.hncDir).Items) > 0
	return loopFlags{CtPrecise: ctPreciseActive(), Enforcing: enf}
}

// 应用时长「每轮最多记多少秒」的上限。基准 10s 节拍下是 appTimeMaxTickSec(20s, 防休眠/卡顿
// 凭空多算); app_usage 进入 30s 后台档时放宽到 40s, 否则每轮只记 20s 会少算三分之一。
var appTimeCapSec atomic.Int64

func appTimeTickCap() int {
	if c := int(appTimeCapSec.Load()); c > appTimeMaxTickSec {
		return c
	}
	return appTimeMaxTickSec
}

// appTimeSetCapFor 按 app_usage 当前间隔设置上限(只放宽到 ≤40s 的档; 更慢的档没有客户端, 回来时重置)
func appTimeSetCapFor(d time.Duration) {
	c := int64(0)
	if sec := int64(d / time.Second); sec > 10 && sec <= 2*appTimeMaxTickSec {
		c = sec + 10
	}
	appTimeCapSec.Store(c)
}

// appTimeResetLast 下一轮按基准间隔记时长(从慢档回来时调用)
func appTimeResetLast() {
	appUsage.mu.Lock()
	appTimeLastTick = time.Time{}
	appUsage.mu.Unlock()
}
