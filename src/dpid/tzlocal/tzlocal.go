// Package tzlocal v5.12: 在 Android 上取得真正的本地时区。
//
// 背景: GOOS=android 时 Go 标准库的 time.initLocal 直接把 time.Local 设成
// UTC(zoneinfo_android.go: "TODO(elias.naur): getprop persist.sys.timezone"),
// 连 TZ 环境变量都不看。dpid / hnc_watchdog 从未自行设置 time.Local, 于是所有
// "本地时间" 逻辑实际按 UTC 跑: 免打扰 23-7 在东八区变成 07:00-15:00(白天静音、
// 半夜推送), 月度配额的 "自然月" 从 1 号 08:00 起算。
//
// 另外标准库 LoadLocation 在 Android 只查 /system/usr/share/zoneinfo/tzdata 与
// /data/misc/zoneinfo/current/tzdata; Android 10+ 的时区库搬进了 APEX
// (/apex/com.android.tzdata/etc/tz/tzdata), 新机型上标准库可能加载失败,
// 所以这里自己解析 Android 打包格式的 tzdata, 最后再退到 `date +%z` 固定偏移。
package tzlocal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	once sync.Once
	loc  *time.Location
)

// Location 返回进程应当使用的本地时区。非 Android 平台直接返回 time.Local。
// 结果缓存(时区在进程生命周期内视为不变)。任何失败都退回 time.Local, 绝不返回 nil。
func Location() *time.Location {
	once.Do(func() {
		loc = resolve(runtime.GOOS, getprop, os.ReadFile, dateOffset)
	})
	return loc
}

// Android tzdata 可能的位置(新 → 旧)。
var tzdataPaths = []string{
	"/apex/com.android.tzdata/etc/tz/tzdata",
	"/apex/com.android.runtime/etc/tz/tzdata",
	"/data/misc/zoneinfo/current/tzdata",
	"/system/usr/share/zoneinfo/tzdata",
}

func resolve(goos string, prop func(string) string, readFile func(string) ([]byte, error),
	offset func() (int, bool)) *time.Location {
	if goos != "android" {
		return time.Local
	}
	name := strings.TrimSpace(prop("persist.sys.timezone"))
	if name != "" {
		if l, err := time.LoadLocation(name); err == nil {
			return l
		}
		for _, p := range tzdataPaths {
			b, err := readFile(p)
			if err != nil {
				continue
			}
			if tzif, err := extractTZif(b, name); err == nil {
				if l, err := time.LoadLocationFromTZData(name, tzif); err == nil {
					return l
				}
			}
		}
	}
	if off, ok := offset(); ok {
		if name == "" {
			name = "LOCAL"
		}
		return time.FixedZone(name, off)
	}
	return time.Local
}

// extractTZif 从 Android 打包的 tzdata 里取出指定时区的 TZif 数据。
// 格式(libcore ZoneInfoDB): 12 字节 "tzdataYYYYx\0" 魔数 + 3 个大端 int32
// (index_offset, data_offset, final_offset); 索引项每项 52 字节:
// name[40] + offset + length + unused。
func extractTZif(b []byte, name string) ([]byte, error) {
	const hdr = 24
	const entry = 52
	if len(b) < hdr || !bytes.HasPrefix(b, []byte("tzdata")) {
		return nil, errors.New("tzdata: bad header")
	}
	idx := int64(binary.BigEndian.Uint32(b[12:16]))
	data := int64(binary.BigEndian.Uint32(b[16:20]))
	if idx < hdr || data < idx || data > int64(len(b)) {
		return nil, errors.New("tzdata: bad offsets")
	}
	for p := idx; p+entry <= data; p += entry {
		e := b[p : p+entry]
		n := e[:40]
		if i := bytes.IndexByte(n, 0); i >= 0 {
			n = n[:i]
		}
		if string(n) != name {
			continue
		}
		off := data + int64(binary.BigEndian.Uint32(e[40:44]))
		ln := int64(binary.BigEndian.Uint32(e[44:48]))
		if off < data || ln <= 0 || off+ln > int64(len(b)) {
			return nil, errors.New("tzdata: bad entry")
		}
		return b[off : off+ln], nil
	}
	return nil, errors.New("tzdata: zone not found")
}

func getprop(key string) string {
	out, err := exec.Command("getprop", key).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// dateOffset 用 toybox `date +%z`(bionic 自己会读 persist.sys.timezone)取当前
// UTC 偏移秒数, 作为最后兜底(固定偏移, 不含夏令时切换; 中国无夏令时)。
func dateOffset() (int, bool) {
	out, err := exec.Command("date", "+%z").Output()
	if err != nil {
		return 0, false
	}
	return parseOffset(strings.TrimSpace(string(out)))
}

// parseOffset 解析 "+0800" / "-0530" 形式。
func parseOffset(s string) (int, bool) {
	if len(s) != 5 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	hh, err1 := strconv.Atoi(s[1:3])
	mm, err2 := strconv.Atoi(s[3:5])
	if err1 != nil || err2 != nil || hh > 14 || mm > 59 {
		return 0, false
	}
	off := hh*3600 + mm*60
	if s[0] == '-' {
		off = -off
	}
	return off, true
}
