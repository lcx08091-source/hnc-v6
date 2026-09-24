package apkscan

// v5.15: 常驻调度。dpid 启动后延迟 InitialDelay 做第一轮, 之后每 Interval
// 一轮; 输出文件 generated_at 仍在 Interval 内就跳过(dpid 频繁重启时不会
// 反复全量扫)。另外每 PollEvery 检查一次请求标记文件(httpd「立即扫描」的
// 第二条触发路径), 存在就删掉并立即扫描, 不看新鲜度。

import (
	"context"
	"errors"
	"log"
	"os"
	"time"
)

// DaemonOptions 是常驻调度参数。零值字段用默认值。
type DaemonOptions struct {
	InitialDelay time.Duration // 默认 10 分钟
	Interval     time.Duration // 默认 24 小时
	PollEvery    time.Duration // 请求文件检查周期, 默认 60 秒
	RequestFile  string        // 标记文件路径, 空则不启用
	OnDone       func(*Output, error)
}

// RunDaemon 阻塞运行直到 ctx 取消。
func RunDaemon(ctx context.Context, s *Scanner, d DaemonOptions) {
	if d.InitialDelay <= 0 {
		d.InitialDelay = 10 * time.Minute
	}
	if d.Interval <= 0 {
		d.Interval = 24 * time.Hour
	}
	if d.PollEvery <= 0 {
		d.PollEvery = 60 * time.Second
	}
	now := s.opt.Now
	nextDue := now().Add(d.InitialDelay)

	run := func(why string) {
		out, err := s.Scan(ctx)
		switch {
		case err == nil:
			log.Printf("apkscan(%s): apps=%d scanned=%d reused=%d skipped=%d failed=%d sdk=%d %dms -> %s",
				why, out.AppCount, out.Stats.Scanned, out.Stats.Reused, out.Stats.Skipped,
				out.Stats.Failed, len(out.SDKSuffixes), out.ScanMS, s.opt.OutPath)
		case errors.Is(err, context.Canceled), errors.Is(err, ErrBusy):
		default:
			log.Printf("WARN: apkscan(%s): %v", why, err)
		}
		if d.OnDone != nil {
			d.OnDone(out, err)
		}
	}

	tk := time.NewTicker(d.PollEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		if d.RequestFile != "" {
			if _, err := os.Stat(d.RequestFile); err == nil {
				_ = os.Remove(d.RequestFile)
				run("request")
				nextDue = now().Add(d.Interval)
				continue
			}
		}
		t := now()
		if t.Before(nextDue) {
			continue
		}
		if gen := ReadGeneratedAt(s.opt.OutPath); gen > 0 {
			fresh := time.Unix(gen, 0).Add(d.Interval)
			if t.Before(fresh) {
				nextDue = fresh
				continue
			}
		}
		run("schedule")
		nextDue = now().Add(d.Interval)
	}
}
