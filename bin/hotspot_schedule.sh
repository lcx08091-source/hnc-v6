#!/system/bin/sh
# hotspot_schedule.sh — 定时开关热点 / 只在充电时开热点(v5.12)
#
# 背景: rules.json 里一直有 hotspot_time_enable / hotspot_time_start /
# hotspot_time_end / hotspot_charging_only 四个字段, hotspot_autostart.sh
# 的注释也写着支持, 但从来没有任何代码读取它们。本脚本把它们落地。
#
# 语义(边沿触发, 只在"应该开/应该关"发生变化的那一刻动作):
#   - 期望状态 want = 在时段内(未启用定时则恒真) 且 在充电(未启用则恒真)
#   - want 由关变开 → 热点没开就开; want 由开变关 → 热点开着就关
#   - 两次切换之间不干预: 用户在时段外手动开的热点不会被反复关掉
#   - 两项都没启用 → 清掉状态文件, 什么都不做
# 时段: HH:MM, 左闭右开; 开始 > 结束 表示跨午夜(如 22:00-07:00)。
#
# 调用方: watchdog.sh 主循环每轮一次(开销: 读一次 rules.json + 一个 sysfs 文件)。
#         hotspot_autostart.sh 开机自启前用 --check 询问是否允许。
# 用法: hotspot_schedule.sh [--check] [--dry-run]
#   --check    只判断当前是否允许开热点: 允许 exit 0, 不允许 exit 1(不动作)
#   --dry-run  打印判断过程与将执行的动作, 不真的开关热点
# 测试钩子: HNC_SCHED_NOW=HH:MM 覆盖当前时间; HNC_SCHED_CHARGING=1|0 覆盖充电状态;
#           HNC_POWER_SUPPLY_DIR 覆盖 /sys/class/power_supply。

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RULES="$HNC_DIR/data/rules.json"
RUN="$HNC_DIR/run"
LAST="$RUN/hotspot_schedule.last"
LOG="$HNC_DIR/logs/hotspot.log"
PS_DIR=${HNC_POWER_SUPPLY_DIR:-/sys/class/power_supply}
MODE=run
case "$1" in --check) MODE=check ;; --dry-run) MODE=dry ;; esac

log() { { echo "$(date '+%Y-%m-%d %H:%M:%S') [schedule] $*" >> "$LOG"; } 2>/dev/null; }
say() { [ "$MODE" = "dry" ] && echo "$*"; }

[ -f "$RULES" ] || exit 0
FLAT=$(tr -d '\r\n' < "$RULES" 2>/dev/null)
get_bool() { printf '%s' "$FLAT" | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*(true|false)" | head -1 | grep -oE 'true|false'; }
get_str()  { printf '%s' "$FLAT" | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed 's/.*:[[:space:]]*"//; s/"$//'; }

T_ON=$(get_bool hotspot_time_enable)
C_ON=$(get_bool hotspot_charging_only)
if [ "$T_ON" != "true" ] && [ "$C_ON" != "true" ]; then
    rm -f "$LAST" 2>/dev/null
    say "schedule disabled"
    exit 0
fi

# HH:MM → 当天分钟数; 非法返回空
to_min() {
    case "$1" in
        [0-9]:[0-5][0-9]|[01][0-9]:[0-5][0-9]|2[0-3]:[0-5][0-9]) ;;
        *) return 1 ;;
    esac
    _h=${1%%:*}; _m=${1##*:}
    echo $(( ${_h#0} * 60 + ${_m#0} ))
}

in_window=1
if [ "$T_ON" = "true" ]; then
    s=$(to_min "$(get_str hotspot_time_start)") || s=""
    e=$(to_min "$(get_str hotspot_time_end)") || e=""
    now=$(to_min "${HNC_SCHED_NOW:-$(date +%H:%M)}") || now=""
    if [ -z "$s" ] || [ -z "$e" ] || [ -z "$now" ]; then
        log "invalid time window start=$(get_str hotspot_time_start) end=$(get_str hotspot_time_end), ignore"
        in_window=1
    elif [ "$s" -eq "$e" ]; then
        in_window=1                                   # 开始=结束: 视为全天
    elif [ "$s" -lt "$e" ]; then
        [ "$now" -ge "$s" ] && [ "$now" -lt "$e" ] && in_window=1 || in_window=0
    else
        [ "$now" -ge "$s" ] || [ "$now" -lt "$e" ] && in_window=1 || in_window=0   # 跨午夜
    fi
fi

# 充电判断: 电池状态 Charging/Full, 或任一 usb/ac/wireless 供电 online=1
is_charging() {
    [ -n "$HNC_SCHED_CHARGING" ] && { [ "$HNC_SCHED_CHARGING" = "1" ]; return; }
    for b in "$PS_DIR"/battery "$PS_DIR"/bms; do
        [ -r "$b/status" ] || continue
        case "$(cat "$b/status" 2>/dev/null)" in Charging|Full) return 0 ;; esac
    done
    for p in "$PS_DIR"/*; do
        [ -r "$p/online" ] || continue
        case "$(cat "$p/type" 2>/dev/null)" in Battery|BMS) continue ;; esac
        [ "$(cat "$p/online" 2>/dev/null)" = "1" ] && return 0
    done
    return 1
}
charging_ok=1
if [ "$C_ON" = "true" ]; then is_charging && charging_ok=1 || charging_ok=0; fi

want=off
[ "$in_window" = "1" ] && [ "$charging_ok" = "1" ] && want=on
say "time_enable=$T_ON in_window=$in_window charging_only=$C_ON charging_ok=$charging_ok want=$want"

[ "$MODE" = "check" ] && { [ "$want" = "on" ]; exit $?; }

last=$(cat "$LAST" 2>/dev/null)
if [ "$last" = "$want" ]; then
    say "no transition (last=$last)"
    exit 0
fi

active=0
case "$(cat "$RUN/hnc_state" 2>/dev/null)" in ACTIVE:*) active=1 ;; esac

AUTO="$HNC_DIR/bin/hotspot_autostart.sh"
if [ "$want" = "on" ] && [ "$active" = "0" ]; then
    # 首次运行(last 为空)且不在自启模式: 不主动开, 只记录, 避免装模块/开定时的
    # 瞬间突然把热点打开。开机自启由 hotspot_autostart.sh(--check)负责。
    if [ -z "$last" ]; then
        say "first run: record only"
    elif [ "$MODE" = "dry" ]; then
        say "ACTION: start hotspot"
    else
        log "transition $last -> on (window=$in_window charging=$charging_ok): start hotspot"
        nohup sh "$AUTO" start-now >/dev/null 2>&1 &
    fi
elif [ "$want" = "off" ] && [ "$active" = "1" ] && [ -n "$last" ]; then
    if [ "$MODE" = "dry" ]; then
        say "ACTION: stop hotspot"
    else
        log "transition $last -> off (window=$in_window charging=$charging_ok): stop hotspot"
        sh "$AUTO" stop >/dev/null 2>&1
    fi
fi

[ "$MODE" = "dry" ] || { mkdir -p "$RUN" 2>/dev/null; echo "$want" > "$LAST.tmp" 2>/dev/null && mv -f "$LAST.tmp" "$LAST" 2>/dev/null; }
exit 0
