#!/system/bin/sh
# hnc_clock.sh — v5.20 共享时钟健壮性 helper(shell 侧; Go 侧见 daemon/hnc_httpd/clock_guard.go)
#
# Android 可能在 NTP 同步前就跑起服务(时钟停在 1970/2000, 或 RTC 过期停在几天前),
# 运行中也可能被 NTP/用户改时间。按日期命名/按日期归档的写入器(stats_sample 的
# 采样 ts 与跨日 rollup、stats_rollup 的保留期清理与 .backup-YYYYMMDD、
# cleanup_stale_rules 的 TTL 判定、watchdog 的 online_hours 日字段、开机备份)
# 在时钟不可信时应跳过, 否则会写出 1970 的日期、或被跑到未来的时钟把历史/规则当过期删掉。
#
# 规则与 httpd 一致:
#   可信 = 时间戳 ≥ 2025-01-01T00:00:00Z 且 不早于高水位(data/clock_hwm) − 600s
#   高水位 = 各写入器在时钟可信时记下的最晚时间(单行 unix 秒; Go/shell 共用)
#   跳变 = 相邻两次调用之间 墙钟间隔 与 /proc/uptime 间隔 相差 > 600s
#
# 用法(source 后调用函数, 或直接当命令):
#   . "$HNC_DIR/bin/hnc_clock.sh"
#   hnc_clock_sane [now]        → rc 0 可信 / 1 不可信
#   hnc_clock_note [now]        → 推进高水位(仅在可信时调用; 至多每 300s 落盘一次)
#   hnc_clock_jump <name> [now] → rc 0 = 刚发生跳变(stdout 输出偏差秒数) / 1 = 无跳变;
#                                  状态记在 run/clock.<name>
#   sh hnc_clock.sh sane|note|jump <name>|status
# 测试注入: HNC_CLOCK_NOW(墙钟秒)、HNC_CLOCK_UPTIME(单调秒)

HNC_CLOCK_MIN_TS=1735689600   # 2025-01-01T00:00:00Z
HNC_CLOCK_TOLERANCE=600       # 允许落后高水位的秒数(小幅 NTP 回拨)
HNC_CLOCK_JUMP=600            # 跳变阈值
HNC_CLOCK_PERSIST_EVERY=300   # 高水位落盘节流

_hnc_clock_dir() { echo "${HNC_DIR:-/data/local/hnc}"; }

hnc_clock_now() {
    if [ -n "$HNC_CLOCK_NOW" ]; then echo "$HNC_CLOCK_NOW"; return 0; fi
    date +%s 2>/dev/null
}

hnc_clock_uptime() {
    if [ -n "$HNC_CLOCK_UPTIME" ]; then echo "$HNC_CLOCK_UPTIME"; return 0; fi
    local up _r
    if read -r up _r < /proc/uptime 2>/dev/null && [ -n "$up" ]; then
        echo "${up%%.*}"; return 0
    fi
    echo ""
}

hnc_clock_hwm() {
    local v
    v=$(cat "$(_hnc_clock_dir)/data/clock_hwm" 2>/dev/null | tr -dc '0-9')
    echo "${v:-0}"
}

hnc_clock_sane() {
    local now=${1:-$(hnc_clock_now)} hwm
    case "$now" in ''|*[!0-9]*) return 1 ;; esac
    [ "$now" -ge "$HNC_CLOCK_MIN_TS" ] || return 1
    hwm=$(hnc_clock_hwm)
    if [ "$hwm" -gt 0 ] && [ "$now" -lt $((hwm - HNC_CLOCK_TOLERANCE)) ]; then
        return 1
    fi
    return 0
}

hnc_clock_note() {
    local now=${1:-$(hnc_clock_now)} hwm f tmp
    hnc_clock_sane "$now" || return 1
    hwm=$(hnc_clock_hwm)
    [ "$now" -ge $((hwm + HNC_CLOCK_PERSIST_EVERY)) ] || return 0
    f="$(_hnc_clock_dir)/data/clock_hwm"
    tmp="$f.tmp.$$"
    mkdir -p "$(_hnc_clock_dir)/data" 2>/dev/null
    echo "$now" > "$tmp" 2>/dev/null && mv -f "$tmp" "$f" 2>/dev/null
    rm -f "$tmp" 2>/dev/null
    return 0
}

hnc_clock_jump() {
    local name=$1 now=${2:-$(hnc_clock_now)} up st pw pu dw du d
    [ -n "$name" ] || return 1
    up=$(hnc_clock_uptime)
    case "$now" in ''|*[!0-9]*) return 1 ;; esac
    case "$up" in ''|*[!0-9]*) return 1 ;; esac
    st="$(_hnc_clock_dir)/run/clock.$name"
    pw=""; pu=""
    [ -f "$st" ] && read -r pw pu < "$st" 2>/dev/null
    mkdir -p "$(_hnc_clock_dir)/run" 2>/dev/null
    echo "$now $up" > "$st" 2>/dev/null
    case "$pw" in ''|*[!0-9]*) return 1 ;; esac
    case "$pu" in ''|*[!0-9]*) return 1 ;; esac
    # uptime 变小 = 重启过(run/ 残留), 不可比
    [ "$up" -ge "$pu" ] || return 1
    dw=$((now - pw)); du=$((up - pu)); d=$((dw - du))
    if [ "$d" -gt "$HNC_CLOCK_JUMP" ] || [ "$d" -lt $((0 - HNC_CLOCK_JUMP)) ]; then
        echo "$d"
        return 0
    fi
    return 1
}

# 直接执行时的 CLI(被 source 时 $0 不是本文件, 不触发)
case "${0##*/}" in
    hnc_clock.sh)
        case "$1" in
            sane)   hnc_clock_sane "$2"; exit $? ;;
            note)   hnc_clock_note "$2"; exit $? ;;
            jump)   hnc_clock_jump "$2" "$3"; exit $? ;;
            status)
                now=$(hnc_clock_now)
                if hnc_clock_sane "$now"; then s=1; else s=0; fi
                echo "now=$now sane=$s high_water=$(hnc_clock_hwm) min_ts=$HNC_CLOCK_MIN_TS"
                exit 0 ;;
            *) echo "Usage: $0 {sane [now]|note [now]|jump <name> [now]|status}" >&2; exit 2 ;;
        esac ;;
esac
