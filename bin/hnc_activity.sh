#!/system/bin/sh
# hnc_activity.sh — v5.22 功耗: 读 run/activity.json(hnc_httpd 每 15s 探测、≤60s 刷新)
#
# 只用 shell 内建(read / case / 参数展开 / 算术), 不 fork —— 循环里每轮都读也几乎零开销。
# 被 watchdog.sh / hnc_offload_guard.sh 以 `.` 引入。
#
# activity.json 是单行 JSON, 字段顺序固定(见 daemon/hnc_httpd/power_activity.go Activity):
#   {"ts":..,"level":"hotspot_off|no_clients|background|active|unknown","screen_on":..,
#    "screen_known":..,"screen_source":"..","hotspot_active":..,"hotspot_iface":"..",
#    "clients_online":N,"webui_active":..,"sse_clients":N,"last_api_ago_s":N,"ct_precise":..,"known":..}
#
# 间隔策略与 Go 侧 powerInterval(power_sched.go)同一张表; 改数值两边一起改。
#
# 用法:
#   hnc_act_load [now]   解析到 ACT_* 变量; 给了 now(秒)时还判新鲜度 → ACT_OK=1
#                        没文件/解析不了/过期: ACT_OK=0, 其余变量取「保守」值(视为活跃)
# (v5.33: 只剩 hnc_act_load。hnc_act_sleep_until 是 shell offload 守护循环的早醒睡眠,
#  循环删了以后由 Go 看门狗 offload_sched.go 的 offloadEarlyWake 负责; hnc_act_quiet
#  没有调用者。)
#
# 新鲜度上限与 Go 读取器 src/dpid/activity.MaxAge 一致(120 秒; 原来 shell 180、Go 120,
# 同一份文件两边判新鲜不一样), TestPowerShellMirrorConstants 核对。

HNC_ACT_MAX_AGE=${HNC_ACT_MAX_AGE:-120}

hnc_act_load() {
    ACT_OK=0
    ACT_TS=0
    ACT_LEVEL=unknown
    ACT_SCREEN_OFF=0
    ACT_SCREEN_ON=0
    ACT_HOTSPOT=1
    ACT_CLIENTS=1
    ACT_WEBUI=1
    _act_f="${HNC_DIR:-/data/local/hnc}/run/activity.json"
    [ -r "$_act_f" ] || return 1
    _act_l=""
    IFS= read -r _act_l 2>/dev/null < "$_act_f"
    case "$_act_l" in
        '{"ts":'*) ;;
        *) return 1 ;;
    esac
    _act_v=${_act_l#*\"ts\":}
    _act_v=${_act_v%%[,\}]*}
    case "$_act_v" in ''|*[!0-9]*) return 1 ;; esac
    ACT_TS=$_act_v
    case "$_act_l" in
        *'"level":"hotspot_off"'*) ACT_LEVEL=hotspot_off ;;
        *'"level":"no_clients"'*)  ACT_LEVEL=no_clients ;;
        *'"level":"background"'*)  ACT_LEVEL=background ;;
        *'"level":"active"'*)      ACT_LEVEL=active ;;
    esac
    case "$_act_l" in *'"hotspot_active":false'*) ACT_HOTSPOT=0 ;; esac
    case "$_act_l" in *'"webui_active":false'*) ACT_WEBUI=0 ;; esac
    case "$_act_l" in
        *'"screen_on":false,"screen_known":true'*) ACT_SCREEN_OFF=1 ;;
        *'"screen_on":true,"screen_known":true'*)  ACT_SCREEN_ON=1 ;;
    esac
    _act_v=${_act_l#*\"clients_online\":}
    _act_v=${_act_v%%[,\}]*}
    case "$_act_v" in ''|*[!0-9]*) ;; *) ACT_CLIENTS=$_act_v ;; esac
    if [ -n "$1" ]; then
        case "$1" in ''|*[!0-9]*) return 0 ;; esac
        # 新鲜: 不早于 now-MAX_AGE, 也不比 now 晚 60s 以上(时钟回拨保护)
        if [ $(($1 - ACT_TS)) -le "$HNC_ACT_MAX_AGE" ] && [ $((ACT_TS - $1)) -le 60 ]; then
            [ "$ACT_LEVEL" != unknown ] && ACT_OK=1
        fi
    fi
    return 0
}
