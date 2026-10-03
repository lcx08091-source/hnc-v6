// Package clockhwm —— 时钟可信规则与高水位读取的唯一权威(v5.26 T6)。
//
// 「时钟是否可信(≥2025 且 不早于高水位 − 600 秒)」此前有三份:
// daemon/hnc_httpd/clock_guard.go 的 clockSaneAt(本地年份判断)、
// bin/hnc_clock.sh 的 hnc_clock_sane(shell, 给脚本用)、hnc_watchdog
// duties.go 的 clockSaneNow。三份的「2025 边界」口径原本就有细微
// 差异(本地年份 vs UTC 时间戳), 本包以 MinUnix(UTC)为准统一。
// shell 版保留(给 shell 脚本用), 由镜像测试锁定一致。
//
// 唯一允许重置高水位的地方仍是 clock_guard.go(它的自愈与跳变检测
// 逻辑不动), 本包只读。
package clockhwm

import (
	"os"
	"strconv"
	"strings"
)

const (
	// MinUnix 2025-01-01T00:00:00Z —— 低于此视为开机未对时(1970/2000)。
	MinUnix int64 = 1735689600
	// BackTolerance 允许落后高水位的秒数(小幅 NTP 回拨)。
	BackTolerance int64 = 600
)

// ReadHWM 读高水位文件(单行 unix 秒)。文件缺失/损坏/非法 → 0。
func ReadHWM(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]), 10, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// Sane 纯函数: now ≥ MinUnix 且(hwm ≤ 0 或 now ≥ hwm − BackTolerance)。
func Sane(nowUnix, hwm int64) bool {
	if nowUnix < MinUnix {
		return false
	}
	if hwm > 0 && nowUnix < hwm-BackTolerance {
		return false
	}
	return true
}
