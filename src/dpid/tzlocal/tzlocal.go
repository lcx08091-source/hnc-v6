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
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	once sync.Once
	loc  *time.Location
)

const (
	persistentPropsPath = "/data/property/persistent_properties"
	systemBuildPropPath = "/system/build.prop"
	timezonePropKey     = "persist.sys.timezone"
	subprocTimeout      = 2 * time.Second
	subprocWaitDelay    = 500 * time.Millisecond
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
	name := readTimezoneFromFiles(readFile)
	if name == "" && prop != nil {
		name = strings.TrimSpace(prop(timezonePropKey))
	}
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
	if offset != nil {
		if off, ok := offset(); ok {
			if name == "" {
				name = "LOCAL"
			}
			return time.FixedZone(name, off)
		}
	}
	return time.Local
}

// readTimezoneFromFiles 优先纯 Go 读取 /data/property/persistent_properties 与
// /system/build.prop 提取 persist.sys.timezone, 避免冷启动 fork getprop。
func readTimezoneFromFiles(readFile func(string) ([]byte, error)) string {
	if readFile == nil {
		return ""
	}
	if b, err := readFile(persistentPropsPath); err == nil && len(b) > 0 {
		if tz := extractPersistentPropTimezone(b); tz != "" {
			return tz
		}
	}
	if b, err := readFile(systemBuildPropPath); err == nil && len(b) > 0 {
		if tz := extractBuildPropTimezone(b); tz != "" {
			return tz
		}
	}
	return ""
}

// extractBuildPropTimezone 解析 key=value 文本属性(如 /system/build.prop)。
func extractBuildPropTimezone(b []byte) string {
	var found string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, timezonePropKey+"="); ok {
			v = strings.TrimSpace(v)
			if isValidTimezoneName(v) {
				found = v
			}
		}
	}
	return found
}

// extractPersistentPropTimezone 从 Android /data/property/persistent_properties 提取
// persist.sys.timezone。优先按 AOSP PersistentProperties protobuf wire 格式精确解析,
// 同时兼容文本 key=value 及原始二进制块中的 ASCII 时区串扫描。
func extractPersistentPropTimezone(b []byte) string {
	if tz, seenKey := parsePersistentPropsProto(b); seenKey {
		return tz
	}
	if tz := extractBuildPropTimezone(b); tz != "" {
		return tz
	}
	return scanPersistentPropASCII(b)
}

func parsePersistentPropsProto(b []byte) (found string, seenKey bool) {
	for off := 0; off < len(b); {
		tag, n := readUvarint(b[off:])
		if n <= 0 {
			break
		}
		off += n
		switch tag & 7 {
		case 0:
			_, vn := readUvarint(b[off:])
			if vn <= 0 {
				return found, seenKey
			}
			off += vn
		case 1:
			if len(b)-off < 8 {
				return found, seenKey
			}
			off += 8
		case 2:
			ln, lnBytes := readUvarint(b[off:])
			if lnBytes <= 0 || ln > uint64(len(b)-off-lnBytes) {
				return found, seenKey
			}
			off += lnBytes
			rec := b[off : off+int(ln)]
			off += int(ln)
			if (tag >> 3) == 1 {
				if k, v, ok := parsePersistentPropRecord(rec); ok && k == timezonePropKey {
					seenKey = true
					if isValidTimezoneName(v) {
						found = v
					} else {
						found = ""
					}
				}
			}
		case 5:
			if len(b)-off < 4 {
				return found, seenKey
			}
			off += 4
		default:
			return found, seenKey
		}
	}
	return found, seenKey
}

func parsePersistentPropRecord(rec []byte) (name, val string, ok bool) {
	for off := 0; off < len(rec); {
		tag, n := readUvarint(rec[off:])
		if n <= 0 {
			return "", "", false
		}
		off += n
		switch tag & 7 {
		case 0:
			_, vn := readUvarint(rec[off:])
			if vn <= 0 {
				return "", "", false
			}
			off += vn
		case 1:
			if len(rec)-off < 8 {
				return "", "", false
			}
			off += 8
		case 2:
			ln, lnBytes := readUvarint(rec[off:])
			if lnBytes <= 0 || ln > uint64(len(rec)-off-lnBytes) {
				return "", "", false
			}
			off += lnBytes
			s := string(rec[off : off+int(ln)])
			off += int(ln)
			switch tag >> 3 {
			case 1:
				name = s
			case 2:
				val = strings.TrimSpace(s)
			}
		case 5:
			if len(rec)-off < 4 {
				return "", "", false
			}
			off += 4
		default:
			return "", "", false
		}
	}
	return name, val, name != ""
}

func readUvarint(b []byte) (uint64, int) {
	v, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0
	}
	return v, n
}

func scanPersistentPropASCII(b []byte) string {
	needle := []byte(timezonePropKey)
	var found string
	searchFrom := 0
	for searchFrom < len(b) {
		idx := bytes.Index(b[searchFrom:], needle)
		if idx < 0 {
			break
		}
		pos := searchFrom + idx + len(needle)
		searchFrom = pos

		// Protobuf field 2 tag (0x12) + varint length immediately following field 1 name.
		if pos+2 <= len(b) && b[pos] == 0x12 {
			vlen, n := readUvarint(b[pos+1:])
			if n > 0 && vlen > 0 && vlen <= 64 && pos+1+n+int(vlen) <= len(b) {
				cand := strings.TrimSpace(string(b[pos+1+n : pos+1+n+int(vlen)]))
				if isValidTimezoneName(cand) {
					found = cand
				} else {
					found = ""
				}
				continue
			}
		}

		// Generic binary/NUL-delimited ASCII scan: only skip control bytes / '=' / space,
		// never skip '.' or '/' which could mask a "../" path traversal prefix.
		p := pos
		aborted := false
		for skipped := 0; p < len(b) && skipped < 8; skipped++ {
			c := b[p]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				break
			}
			if c > 0x20 && c != '=' {
				aborted = true
				break
			}
			p++
		}
		if aborted {
			continue
		}
		end := p
		for end < len(b) && end-p < 64 && isTZChar(b[end]) {
			end++
		}
		cand := string(b[p:end])
		if isValidTimezoneName(cand) {
			found = cand
		}
	}
	return found
}

func isTZChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '/' || c == '_' || c == '-' || c == '+'
}

func isValidTimezoneName(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	first := s[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')) {
		return false
	}
	if strings.Contains(s, "..") || strings.HasSuffix(s, "/") || strings.Contains(s, "//") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTZChar(s[i]) {
			return false
		}
	}
	return true
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

// runSubproc 执行外部兜底命令(getprop / date), 强制 2s 超时 + 独立进程组 Setpgid +
// 超时 SIGKILL 杀进程组 + WaitDelay 防孙进程持管道挂死。
func runSubproc(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
				return nil
			}
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = subprocWaitDelay
	return cmd.Output()
}

func getprop(key string) string {
	out, err := runSubproc(subprocTimeout, "getprop", key)
	if err != nil {
		return ""
	}
	return string(out)
}

// dateOffset 用 toybox `date +%z`(bionic 自己会读 persist.sys.timezone)取当前
// UTC 偏移秒数, 作为最后兜底(固定偏移, 不含夏令时切换; 中国无夏令时)。
func dateOffset() (int, bool) {
	out, err := runSubproc(subprocTimeout, "date", "+%z")
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
