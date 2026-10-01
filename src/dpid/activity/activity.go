// Package activity 读 hnc_httpd 写的 run/activity.json(v5.22 功耗), 给 dpid 的后台
// 循环一个「现在要不要勤快」的信号。间隔数值与 daemon/hnc_httpd/power_sched.go 的
// dpid_* 镜像条目一致(那边有测试对表)。
//
// 文件缺失 / 解析失败 / 过期(>120s, httpd 挂了)→ OK=false → 一律按基准间隔(旧行为)。
package activity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	FileName = "activity.json"
	MaxAge   = 120 * time.Second
	cacheTTL = 5 * time.Second
)

// 档位(与 httpd 相同)
const (
	LevelUnknown    = "unknown"
	LevelHotspotOff = "hotspot_off"
	LevelNoClients  = "no_clients"
	LevelBackground = "background"
	LevelActive     = "active"
)

type file struct {
	Ts            int64  `json:"ts"`
	Level         string `json:"level"`
	ScreenOn      bool   `json:"screen_on"`
	ScreenKnown   bool   `json:"screen_known"`
	HotspotActive bool   `json:"hotspot_active"`
	ClientsOnline int    `json:"clients_online"`
	WebUIActive   bool   `json:"webui_active"`
}

// Snapshot 一次读取的结果
type Snapshot struct {
	OK      bool // 文件新鲜可信
	Level   string
	Quiet   bool // 熄屏且没有界面在看
	Hotspot bool
	Clients int
}

// Parse 纯函数: 文件内容 + 当前时间 → Snapshot
func Parse(b []byte, now time.Time) Snapshot {
	var f file
	if err := json.Unmarshal(b, &f); err != nil || f.Ts <= 0 {
		return Snapshot{Level: LevelUnknown, Hotspot: true, Clients: 1}
	}
	age := now.Sub(time.Unix(f.Ts, 0))
	s := Snapshot{
		Level:   f.Level,
		Quiet:   f.ScreenKnown && !f.ScreenOn && !f.WebUIActive,
		Hotspot: f.HotspotActive,
		Clients: f.ClientsOnline,
	}
	switch f.Level {
	case LevelHotspotOff, LevelNoClients, LevelBackground, LevelActive:
		s.OK = age <= MaxAge && age >= -time.Minute
	default:
		s.Level = LevelUnknown
	}
	if !s.OK {
		return Snapshot{Level: LevelUnknown, Hotspot: true, Clients: 1}
	}
	return s
}

// Reader 带 5 秒缓存的读取器(多个 goroutine 共用)
type Reader struct {
	path string
	now  func() time.Time
	read func(string) ([]byte, error)

	mu   sync.Mutex
	at   time.Time
	last Snapshot
}

func NewReader(runDir string) *Reader {
	return &Reader{path: filepath.Join(runDir, FileName), now: time.Now, read: os.ReadFile}
}

func (r *Reader) Get() Snapshot {
	if r == nil {
		return Snapshot{Level: LevelUnknown, Hotspot: true, Clients: 1}
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.at.IsZero() && now.Sub(r.at) < cacheTTL && !now.Before(r.at) {
		return r.last
	}
	b, err := r.read(r.path)
	if err != nil {
		r.last = Snapshot{Level: LevelUnknown, Hotspot: true, Clients: 1}
	} else {
		r.last = Parse(b, now)
	}
	r.at = now
	return r.last
}

// idle 热点未开或没有在线设备(且信号可信)
func (s Snapshot) idle() bool {
	return s.OK && (s.Level == LevelHotspotOff || s.Level == LevelNoClients)
}

// ConntrackEvery 连接表扫描(基准 15s; 无在线设备 60s)
func ConntrackEvery(s Snapshot) time.Duration {
	if s.idle() {
		return 60 * time.Second
	}
	return 15 * time.Second
}

// StateFlushEvery dpi_state.json 落盘(基准 5s; 无在线设备 30s —— 自检 180s 才判「卡住」)
func StateFlushEvery(s Snapshot) time.Duration {
	if s.idle() {
		return 30 * time.Second
	}
	return 5 * time.Second
}

// BlindFlushEvery 盲态/禁用态的状态落盘(基准 10s; 热点未开 30s)
func BlindFlushEvery(s Snapshot) time.Duration {
	if s.idle() {
		return 30 * time.Second
	}
	return 10 * time.Second
}

// ByteSampleEvery 本机按 uid 字节采样: 自身归因没开 → 0(不采, 调用方 60s 后再看开关);
// 熄屏且无界面 30s; 否则 5s。
func ByteSampleEvery(s Snapshot, enabled bool) time.Duration {
	if !enabled {
		return 0
	}
	if s.OK && s.Quiet {
		return 30 * time.Second
	}
	return 5 * time.Second
}

// CaptureRetryBackoff 抓包口暂时不在(热点关了/接口重建)时的重试间隔: 2s 起翻倍, 上限 30s;
// 确知热点未开时上限 60s。prev=0 表示第一次。
func CaptureRetryBackoff(prev time.Duration, s Snapshot) time.Duration {
	limit := 30 * time.Second
	if s.OK && s.Level == LevelHotspotOff {
		limit = 60 * time.Second
	}
	next := 2 * time.Second
	if prev > 0 {
		next = prev * 2
	}
	if next > limit {
		next = limit
	}
	return next
}
