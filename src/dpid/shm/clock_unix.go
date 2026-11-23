// clock_unix.go 实现跨进程 CLOCK_BOOTTIME 单调时钟读取, 并在 32 位 linux/arm 下优先启用
// SYS_CLOCK_GETTIME64 (403) 消除 Y2038 32 位秒数截断隐患。
package shm

import (
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	clockBoottime     uintptr = 7   // Linux CLOCK_BOOTTIME (包含系统休眠/Doze 时长)
	sysClockGettime64 uintptr = 403 // 32 位 Linux ABI __NR_clock_gettime64 系统调用号
	is32BitArch               = ^uint(0)>>63 == 0
)

var (
	monoStart  = time.Now()
	bootBaseNs = initBootBaseNs()
)

func initBootBaseNs() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 1_000_000_000
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 1_000_000_000
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || sec <= 0 {
		return 1_000_000_000
	}
	return int64(sec * float64(time.Second))
}

func timespec64ToNs(sec, nsec int64) (int64, bool) {
	if sec < 0 || nsec < 0 || nsec >= int64(time.Second) {
		return 0, false
	}
	const maxSafeSec = (math.MaxInt64 - int64(time.Second)) / int64(time.Second)
	if sec > maxSafeSec {
		return math.MaxInt64, true
	}
	ns := sec*int64(time.Second) + nsec
	if ns <= 0 {
		return 0, false
	}
	return ns, true
}

func queryBoottimeNsWith(
	arch32 bool,
	call64 func(ts *[2]int64) syscall.Errno,
	callLegacy func(ts *syscall.Timespec) syscall.Errno,
) (int64, bool) {
	if arch32 {
		var ts64 [2]int64
		errno := call64(&ts64)
		if errno == 0 {
			return timespec64ToNs(ts64[0], ts64[1])
		}
		if errno != syscall.ENOSYS {
			return 0, false
		}
		var tsLegacy syscall.Timespec
		if callLegacy(&tsLegacy) == 0 {
			return timespec64ToNs(int64(tsLegacy.Sec), int64(tsLegacy.Nsec))
		}
		return 0, false
	}

	var tsNative syscall.Timespec
	if callLegacy(&tsNative) == 0 {
		return timespec64ToNs(int64(tsNative.Sec), int64(tsNative.Nsec))
	}
	return 0, false
}

func rawClockGettime64Boottime(ts *[2]int64) syscall.Errno {
	_, _, errno := syscall.Syscall(sysClockGettime64, clockBoottime, uintptr(unsafe.Pointer(&ts[0])), 0)
	return errno
}

func rawClockGettimeLegacyBoottime(ts *syscall.Timespec) syscall.Errno {
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockBoottime, uintptr(unsafe.Pointer(ts)), 0)
	return errno
}

// MonotonicNs 返回单调不减的纳秒时间戳。
// 在 Linux/Android 上直接读取 CLOCK_BOOTTIME 保证跨进程与 Doze 休眠一致性;
// 在 32 位架构 (^uint(0)>>63 == 0) 上优先调用 SYS_CLOCK_GETTIME64 (403) 防止 Y2038 溢出,
// 仅当旧内核返回 ENOSYS 时回退 SYS_CLOCK_GETTIME。
func MonotonicNs() int64 {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if ns, ok := queryBoottimeNsWith(is32BitArch, rawClockGettime64Boottime, rawClockGettimeLegacyBoottime); ok {
			return ns
		}
	}
	d := time.Since(monoStart).Nanoseconds()
	if d < 0 {
		d = 0
	}
	return bootBaseNs + d
}
