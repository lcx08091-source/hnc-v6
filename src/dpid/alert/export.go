package alert

import "time"

// v5.26 T4 导出的薄封装: 全局月度配额检测从 alert.Run 迁到 httpd 的
// limitCtl(与设备配额同一数据源)。httpd 侧生成告警需要这些与旧实现完全
// 一致的辅助函数 —— 与其在 httpd 复制一份, 不如从权威处导出。

func MakeAlertID(kind, mac string, ts int64) string { return makeAlertID(kind, mac, ts) }

func FormatBytes(n uint64) string { return formatBytes(n) }

func LookupHostname(devicesPath, mac string) string { return lookupHostname(devicesPath, mac) }

func InQuietHours(now time.Time, u UnknownDevice) bool { return inQuietHours(now, u) }

func PostNotification(title, body string) error { return postNotification(title, body) }
