package activity

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func line(ts int64, level string, screenOn, known, hot bool, clients int, ui bool) []byte {
	return []byte(fmt.Sprintf(`{"ts":%d,"level":"%s","screen_on":%t,"screen_known":%t,"screen_source":"backlight","hotspot_active":%t,"hotspot_iface":"wlan2","clients_online":%d,"webui_active":%t,"sse_clients":0,"last_api_ago_s":-1,"ct_precise":true,"known":true}`+"\n",
		ts, level, screenOn, known, hot, clients, ui))
}

func TestParse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := Parse(line(now.Unix()-10, LevelHotspotOff, false, true, false, 0, false), now)
	if !s.OK || s.Level != LevelHotspotOff || !s.Quiet || s.Hotspot || s.Clients != 0 {
		t.Fatalf("fresh hotspot_off: %+v", s)
	}
	// 过期 → 不可信, 保守
	if s := Parse(line(now.Unix()-300, LevelHotspotOff, false, true, false, 0, false), now); s.OK || s.Level != LevelUnknown || !s.Hotspot {
		t.Errorf("stale: %+v", s)
	}
	// 未来时间(时钟回拨)
	if s := Parse(line(now.Unix()+600, LevelNoClients, true, true, true, 0, false), now); s.OK {
		t.Errorf("future: %+v", s)
	}
	// 坏文件 / 未知档位
	if s := Parse([]byte("{bad"), now); s.OK {
		t.Error("bad json")
	}
	if s := Parse(line(now.Unix(), "unknown", true, true, true, 1, false), now); s.OK {
		t.Error("unknown level must not be OK")
	}
	// 界面在看 → 不 quiet
	if s := Parse(line(now.Unix(), LevelActive, false, true, true, 2, true), now); !s.OK || s.Quiet {
		t.Errorf("ui: %+v", s)
	}
	// 屏幕未知 → 不 quiet
	if s := Parse(line(now.Unix(), LevelActive, false, false, true, 2, false), now); s.Quiet {
		t.Errorf("unknown screen: %+v", s)
	}
}

func TestIntervals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	off := Parse(line(now.Unix(), LevelHotspotOff, false, true, false, 0, false), now)
	none := Parse(line(now.Unix(), LevelNoClients, true, true, true, 0, false), now)
	bg := Parse(line(now.Unix(), LevelBackground, false, true, true, 2, false), now)
	act := Parse(line(now.Unix(), LevelActive, true, true, true, 2, false), now)
	unk := Snapshot{Level: LevelUnknown}
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ct off", ConntrackEvery(off), 60 * time.Second},
		{"ct none", ConntrackEvery(none), 60 * time.Second},
		{"ct bg", ConntrackEvery(bg), 15 * time.Second},
		{"ct unknown", ConntrackEvery(unk), 15 * time.Second},
		{"flush none", StateFlushEvery(none), 30 * time.Second},
		{"flush act", StateFlushEvery(act), 5 * time.Second},
		{"blind off", BlindFlushEvery(off), 30 * time.Second},
		{"blind unk", BlindFlushEvery(unk), 10 * time.Second},
		{"bytes disabled", ByteSampleEvery(act, false), 0},
		{"bytes bg", ByteSampleEvery(bg, true), 30 * time.Second},
		{"bytes act", ByteSampleEvery(act, true), 5 * time.Second},
		{"bytes unk", ByteSampleEvery(unk, true), 5 * time.Second},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %v want %v", c.name, c.got, c.want)
		}
	}
	// 状态落盘必须远小于自检「卡住」阈值 180s
	for _, s := range []Snapshot{off, none, bg, act, unk} {
		if StateFlushEvery(s) >= 180*time.Second || BlindFlushEvery(s) >= 180*time.Second {
			t.Errorf("flush too slow for %+v", s)
		}
	}
}

func TestCaptureRetryBackoff(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	off := Parse(line(now.Unix(), LevelHotspotOff, false, true, false, 0, false), now)
	var d time.Duration
	var seq []time.Duration
	for i := 0; i < 7; i++ {
		d = CaptureRetryBackoff(d, Snapshot{})
		seq = append(seq, d)
	}
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30}
	for i := range want {
		if seq[i] != want[i]*time.Second {
			t.Fatalf("backoff seq %v", seq)
		}
	}
	if d := CaptureRetryBackoff(50*time.Second, off); d != 60*time.Second {
		t.Errorf("hotspot off cap: %v", d)
	}
}

func TestReaderCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	reads := 0
	r := &Reader{path: "x", now: func() time.Time { return now }, read: func(string) ([]byte, error) {
		reads++
		return line(now.Unix(), LevelNoClients, true, true, true, 0, false), nil
	}}
	if s := r.Get(); !s.OK || s.Level != LevelNoClients {
		t.Fatalf("%+v", s)
	}
	r.Get()
	if reads != 1 {
		t.Errorf("cache miss: reads=%d", reads)
	}
	now = now.Add(6 * time.Second)
	r.Get()
	if reads != 2 {
		t.Errorf("cache should expire: reads=%d", reads)
	}
	r.read = func(string) ([]byte, error) { return nil, errors.New("gone") }
	now = now.Add(6 * time.Second)
	if s := r.Get(); s.OK || !s.Hotspot {
		t.Errorf("missing file should be conservative: %+v", s)
	}
	var nilR *Reader
	if s := nilR.Get(); s.OK {
		t.Error("nil reader")
	}
}
