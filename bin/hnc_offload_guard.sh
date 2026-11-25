#!/system/bin/sh
# hnc_offload_guard.sh — v5.40.0 Android 13–16 T+0 零延迟 offload 慢路径压制与 clsact 协同守卫
#
# 核心增强 (v5.40.0 T2 第 4 & 6 项):
#   1. T+0 主动慢路径压制: auto 模式下只要检测到激活策略(limit_enabled / app_qos / blacklist /
#      global_shaper_enabled 或 data/app_limits.flat 非空), 即使 check_offload 当前处于 CAPABLE
#      (新连接尚无流量窗口), 也立即触发 OFFLOAD_DISABLE_GLOBAL, 消除前数秒千兆旁路泄漏!
#   2. Settings.Global.tether_offload_disabled 三态(null/0/1)无损备份至 run/orig_tether_offload_disabled
#      并在撤销时精确还原(原值 1 保持 1、0 写回 0、null 执行 settings delete), 绝不误改用户原配置!
#   3. 严守硬件安全边界: 仅联动 bin/hnc_mtk_hwnat.sh, 零触碰高危 FOE 节点与厂商守护进程。
#   4. prio 解耦识别: 仅当 mirred 仍霸占旧版 pref 1 时才跳过 clsact; prio 2 mirred 与 pref 1 clsact 完美共存!

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

HNC_DIR="${HNC_DIR:-/data/local/hnc}"
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
RUN="$HNC_DIR/run"
RULES="$HNC_DIR/data/rules.json"
APP_LIMITS_FLAT="$HNC_DIR/data/app_limits.flat"
LOG_FILE="$HNC_DIR/logs/offload_guard.log"
STATUS="$RUN/offload_guard.json"
STATE="$RUN/offload_guard.state"
CLSACT_FLAG="$RUN/offload_guard.clsact"
ORIG_TETHER_FILE="$RUN/orig_tether_offload_disabled"
IPC="$HNC_DIR/bin/hnc_ipc"
CTL="$HNC_DIR/bin/hnc_clsact_ctl"
CHECK_CMD="${HNC_GUARD_CHECK_CMD:-sh $HNC_DIR/bin/check_offload.sh}"
SYS_NET="${HNC_SYS_NET:-/sys/class/net}"
SETTINGS_BIN="${HNC_SETTINGS_BIN:-settings}"
INTERVAL="${HNC_GUARD_INTERVAL:-60}"
RESTORE_AFTER="${HNC_GUARD_RESTORE_AFTER:-3}"
IDLE_INTERVAL="${HNC_GUARD_IDLE_INTERVAL:-300}"
IFB_IFACE="${IFB_IFACE:-ifb0}"

mkdir -p "$RUN" "$HNC_DIR/logs" 2>/dev/null
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [offload-guard] $*" >> "$LOG_FILE" 2>/dev/null; }
now_s() { date +%s 2>/dev/null || echo 0; }
strip_ws() { tr -d ' \t\r\n'; }

if [ -f "$HNC_DIR/bin/hnc_activity.sh" ]; then
    . "$HNC_DIR/bin/hnc_activity.sh"
elif [ -f "${0%/*}/hnc_activity.sh" ]; then
    . "${0%/*}/hnc_activity.sh"
fi
command -v hnc_act_load >/dev/null 2>&1 || {
    hnc_act_load() { ACT_OK=0; return 1; }
}
GUARD_LAST_MODE=""
GUARD_LAST_FB=0
GUARD_LAST_STATE=""
MTK_TETHER_SUPPRESSED=0

guard_soc() {
    if [ -n "${HNC_SOC:-}" ]; then
        echo "$HNC_SOC"
        return 0
    fi
    [ "${HNC_TEST_MODE:-0}" = "1" ] && { echo unknown; return 0; }
    if [ -f "$HNC_DIR/bin/hnc_compat.sh" ]; then
        ( HNC_COMPAT_LIB=1 . "$HNC_DIR/bin/hnc_compat.sh" && hnc_soc_vendor ) 2>/dev/null && return 0
    elif [ -f "${0%/*}/hnc_compat.sh" ]; then
        ( HNC_COMPAT_LIB=1 . "${0%/*}/hnc_compat.sh" && hnc_soc_vendor ) 2>/dev/null && return 0
    fi
    local _hw
    _hw=$(getprop ro.hardware 2>/dev/null; getprop ro.board.platform 2>/dev/null; getprop ro.soc.manufacturer 2>/dev/null)
    case "$(printf '%s' "$_hw" | tr 'A-Z' 'a-z')" in
        *mt[0-9]*|*mediatek*|*dimensity*|*helio*) echo mtk ;;
        *) echo unknown ;;
    esac
}

is_mtk_platform() {
    [ "$(guard_soc)" = "mtk" ] && return 0
    local _r="${HNC_HWNAT_ROOT:-}"
    if [ "${HNC_TEST_MODE:-0}" = "1" ] && [ -z "$_r" ]; then
        return 1
    fi
    [ -e "$_r/dev/mddp" ] || [ -e "$_r/proc/mddp" ] || [ -e "$_r/sys/kernel/mddp" ]
}

guard_mode() {
    local v=""
    if [ -f "$HNC_DIR/bin/hnc_json" ]; then
        v=$(sh "$HNC_DIR/bin/hnc_json" get-top "$RULES" clsact_bpf_mode 2>/dev/null | tr -d '"[:space:]')
    fi
    if [ -z "$v" ]; then
        v=$(grep -o '"clsact_bpf_mode"[[:space:]]*:[[:space:]]*"[a-z]*"' "$RULES" 2>/dev/null | head -n1 | sed 's/.*"\([a-z]*\)"$/\1/')
    fi
    case "$v" in
        auto|on|off) echo "$v" ;;
        *) echo auto ;;
    esac
}

# 检测当前是否存在任何激活的数据面管控策略 (用于 T+0 主动慢路径压制)
has_active_policy() {
    if [ -s "$APP_LIMITS_FLAT" ] && grep -v '^[[:space:]]*#' "$APP_LIMITS_FLAT" 2>/dev/null | grep -q '[^[:space:]]'; then
        return 0
    fi
    [ -f "$RULES" ] || return 1
    local flat
    flat=$(tr -d '\r\n' < "$RULES" 2>/dev/null)
    printf '%s' "$flat" | grep -qE '"(limit_enabled|delay_enabled|sqm_enabled|app_qos|global_shaper_enabled|quic_block|client_isolation_enabled|whitelist_mode)"[[:space:]]*:[[:space:]]*true' && return 0
    printf '%s' "$flat" | grep -qE '"blacklist"[[:space:]]*:[[:space:]]*\[[^]]*"[0-9a-fA-F:]{17}"' && return 0
    return 1
}

SYS_NET_ERR=""
hotspot_iface() {
    local s=""
    SYS_NET_ERR=""
    if [ ! -e "$SYS_NET" ]; then
        SYS_NET_ERR="node_missing"
        return 1
    fi
    if [ ! -r "$SYS_NET" ] || [ ! -x "$SYS_NET" ]; then
        SYS_NET_ERR="permission_denied"
        return 1
    fi
    if [ -e "$RUN/hnc_state" ] && [ ! -r "$RUN/hnc_state" ]; then
        SYS_NET_ERR="permission_denied"
        return 1
    fi
    s=$(sed -n 's/^ACTIVE://p' "$RUN/hnc_state" 2>/dev/null | head -n1 | tr -d ' \r\n')
    case "$s" in *[!a-zA-Z0-9_.:-]*) s="" ;; esac
    if [ -n "$s" ] && [ -e "$SYS_NET/$s" ]; then
        echo "$s"
        return 0
    fi
    return 1
}

is_sta_ap_same_iface() {
    local _ifc="$1" _idj _up _tup _lup
    [ -n "$_ifc" ] || return 1
    [ -r "$RUN/iface_detect.json" ] || return 1
    _idj=$(tr -d '\r\n' < "$RUN/iface_detect.json" 2>/dev/null) || return 1
    _up=$(printf '%s' "$_idj" | grep -oE '"upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    _tup=$(printf '%s' "$_idj" | grep -oE '"tether_upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    _lup=$(printf '%s' "$_idj" | grep -oE '"local_upstream"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    if [ "$_up" = "$_ifc" ] || [ "$_tup" = "$_ifc" ] || [ "$_lup" = "$_ifc" ]; then
        return 0
    fi
    if [ "$_ifc" = "wlan0" ] && printf '%s' "$_idj" | grep -qE '"wlan0_ap"[[:space:]]*:[[:space:]]*true'; then
        return 0
    fi
    return 1
}

st_get() { [ -r "$STATE" ] || return 0; sed -n "s/^$1=//p" "$STATE" 2>/dev/null | head -n1; }
st_save() {
    local _stmp="$STATE.tmp.$$"
    if { echo "fallback=$1"; echo "since=$2"; echo "calm=$3"; } > "$_stmp" 2>/dev/null && [ -s "$_stmp" ]; then
        mv -f "$_stmp" "$STATE" 2>/dev/null || rm -f "$_stmp" 2>/dev/null || true
    else
        rm -f "$_stmp" 2>/dev/null || true
    fi
}

json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\r\n'; }

is_tether_offload_disabled() {
    local _fb=${1:-0}
    if [ "${HNC_TEST_MODE:-0}" = "1" ] && [ -z "${HNC_SETTINGS_BIN:-}" ]; then
        [ "$_fb" = "1" ] || [ "${MTK_TETHER_SUPPRESSED:-0}" = "1" ] || [ -f "$ORIG_TETHER_FILE" ]
        return $?
    fi
    if command -v "$SETTINGS_BIN" >/dev/null 2>&1; then
        local _v
        _v=$("$SETTINGS_BIN" get global tether_offload_disabled 2>/dev/null | strip_ws)
        [ "$_v" = "1" ] && return 0
        if [ "$_v" = "0" ] || [ "$_v" = "null" ]; then
            return 1
        fi
    fi
    [ "$_fb" = "1" ] || [ "${MTK_TETHER_SUPPRESSED:-0}" = "1" ] || [ -f "$ORIG_TETHER_FILE" ]
}

write_status() {
    local fb=false tod=false _rc_code="${9:-ok}" _stmp="$STATUS.tmp.$$"
    [ "$3" = 1 ] && fb=true
    is_tether_offload_disabled "$3" && tod=true
    if printf '{"mode":"%s","offload_state":"%s","fallback_active":%s,"tether_offload_disabled":%s,"since":%s,"reason_code":"%s","detail":"%s","last_check":%s,"slowpath":"%s","clsact":"%s","iface":"%s","hwnat":"%s"}\n' \
        "$1" "$2" "$fb" "$tod" "${4:-0}" "$(json_str "$_rc_code")" "$(json_str "$5")" "$(now_s)" "$6" "$7" "$8" "${HWNAT_ST:-n/a}" > "$_stmp" 2>/dev/null && [ -s "$_stmp" ]; then
        mv -f "$_stmp" "$STATUS" 2>/dev/null || rm -f "$_stmp" 2>/dev/null || true
    else
        rm -f "$_stmp" 2>/dev/null || true
    fi
}

# Android Settings.Global.tether_offload_disabled 三态(null/0/1)无损备份与恢复
tether_hal_suppress() {
    if [ "${HNC_TEST_MODE:-0}" = "1" ] && [ -z "${HNC_SETTINGS_BIN:-}" ]; then
        return 0
    fi
    command -v "$SETTINGS_BIN" >/dev/null 2>&1 || return 0
    if [ ! -f "$ORIG_TETHER_FILE" ]; then
        local _raw _otmp="${ORIG_TETHER_FILE}.tmp.$$"
        _raw=$("$SETTINGS_BIN" get global tether_offload_disabled 2>/dev/null | strip_ws)
        case "$_raw" in
            0|1|null)
                if printf '%s\n' "$_raw" > "$_otmp" 2>/dev/null && [ -s "$_otmp" ]; then
                    mv -f "$_otmp" "$ORIG_TETHER_FILE" 2>/dev/null || { rm -f "$_otmp" 2>/dev/null; return 0; }
                else
                    rm -f "$_otmp" 2>/dev/null
                    return 0
                fi
                log "backed up orig tether_offload_disabled=$_raw"
                ;;
            "")
                return 0
                ;;
            *)
                if printf '%s\n' "$_raw" > "$_otmp" 2>/dev/null && [ -s "$_otmp" ]; then
                    mv -f "$_otmp" "$ORIG_TETHER_FILE" 2>/dev/null || { rm -f "$_otmp" 2>/dev/null; return 0; }
                else
                    rm -f "$_otmp" 2>/dev/null
                    return 0
                fi
                ;;
        esac
    fi
    local _cur
    _cur=$("$SETTINGS_BIN" get global tether_offload_disabled 2>/dev/null | strip_ws)
    if [ "$_cur" != "1" ]; then
        "$SETTINGS_BIN" put global tether_offload_disabled 1 >/dev/null 2>&1 || true
    fi
}

tether_hal_restore() {
    MTK_TETHER_SUPPRESSED=0
    [ -f "$ORIG_TETHER_FILE" ] || return 0
    if [ "${HNC_TEST_MODE:-0}" = "1" ] && [ -z "${HNC_SETTINGS_BIN:-}" ]; then
        rm -f "$ORIG_TETHER_FILE" 2>/dev/null
        return 0
    fi
    command -v "$SETTINGS_BIN" >/dev/null 2>&1 || return 0
    local _orig _rc=0
    _orig=$(strip_ws < "$ORIG_TETHER_FILE" 2>/dev/null)
    case "$_orig" in
        1)
            # 用户原本就是 1, 严禁改回 0!
            log "orig tether_offload_disabled=1, keeping 1 unchanged"
            ;;
        0)
            "$SETTINGS_BIN" put global tether_offload_disabled 0 >/dev/null 2>&1 || _rc=1
            log "restored tether_offload_disabled=0"
            ;;
        null)
            "$SETTINGS_BIN" delete global tether_offload_disabled >/dev/null 2>&1 || _rc=1
            log "deleted tether_offload_disabled to restore null"
            ;;
        *)
            [ -n "$_orig" ] && { "$SETTINGS_BIN" put global tether_offload_disabled "$_orig" >/dev/null 2>&1 || _rc=1; }
            ;;
    esac
    [ "$_rc" -eq 0 ] && rm -f "$ORIG_TETHER_FILE" 2>/dev/null
    return 0
}

vendor_fastpath_probe() {
    local fp
    for fp in /sys/sfe_ipv4/debug_dev /sys/module/shortcut_fe/parameters /sys/module/fast_classifier /sys/devices/platform/dit /sys/module/dit; do
        if [ -e "$fp" ]; then
            log "detected vendor fastpath node: $fp"
        fi
    done
}

slowpath_disable() {
    tether_hal_suppress
    vendor_fastpath_probe
    [ -x "$IPC" ] || { echo unavailable; return; }
    local out rc
    out=$("$IPC" OFFLOAD_DISABLE_GLOBAL 2>/dev/null); rc=$?
    [ "$rc" = 0 ] || { echo unavailable; return; }
    case "$out" in
        *EMPTY*) echo empty ;;
        OK*) echo ok ;;
        *) echo error ;;
    esac
}

slowpath_restore_ipc_only() {
    [ -x "$IPC" ] || return 0
    "$IPC" OFFLOAD_RESTORE_GLOBAL >/dev/null 2>&1 || return 0
    local mac
    for mac in $(tr -d '\r\n' < "$RULES" 2>/dev/null \
                 | grep -oE '"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"[[:space:]]*:[[:space:]]*\{[^{}]*\}' \
                 | grep -E '"limit_enabled"[[:space:]]*:[[:space:]]*true' \
                 | grep -oE '^"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"' | tr -d '"' | tr 'A-F' 'a-f'); do
        "$IPC" OFFLOAD_NOTIFY_LIMIT "$mac" 1 >/dev/null 2>&1 || true
    done
}

slowpath_restore() {
    tether_hal_restore
    slowpath_restore_ipc_only
}

# v5.40.0 T2 第 4 项: ifb0 mirred 已迁至 prio 2 (pref 2)!
# 仅当旧版或无 pref 标记的 mirred 占在 pref 1 时才返回 0(阻塞 clsact); 若 mirred 明确在 pref 2+ 则返回 1(放行 clsact)!
pref1_held_by_mirred() {
    local ifc="$1" dump
    command -v tc >/dev/null 2>&1 || return 1
    dump=$(tc filter show dev "$ifc" ingress 2>/dev/null)
    [ -z "$dump" ] && dump=$(tc filter show dev "$ifc" parent ffff: 2>/dev/null)
    [ -n "$dump" ] || return 1
    printf '%s\n' "$dump" | awk -v ifb="$IFB_IFACE" '
        BEGIN { cur = 0; hit = 0; ifb_lc = tolower(ifb) }
        {
            ln = tolower($0)
            for (i = 1; i < NF; i++) {
                if (($i == "pref" || $i == "prio") && $(i+1) ~ /^[0-9]+$/) {
                    cur = $(i+1) + 0
                }
            }
            if (ln ~ ("mirred.*redirect.*" ifb_lc)) {
                # cur == 1 明确占了 pref 1; cur == 0 表示测试桩无 pref 头行, 按保守占 pref 1 处理
                if (cur == 1 || cur == 0) { hit = 1; exit 0 }
            }
        }
        END { exit(hit ? 0 : 1) }'
}

clsact_artifacts() { [ -f "$HNC_DIR/bin/hnc_clsact.o" ] && [ -x "$CTL" ]; }

clsact_ours_present() {
    "$CTL" check "$1" 2>/dev/null | grep -qE '"(bpf_filter|egress_filter)":true'
}

clsact_apply() {
    local ifc="$1"
    clsact_artifacts || { echo unavailable; return; }
    [ -n "$ifc" ] || { echo unavailable; return; }
    if clsact_ours_present "$ifc"; then
        : > "$CLSACT_FLAG" 2>/dev/null
        sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG_FILE" 2>&1 || true
        echo installed; return
    fi
    if pref1_held_by_mirred "$ifc"; then
        echo skipped_pref1_mirred; return
    fi
    if "$CTL" install "$ifc" >> "$LOG_FILE" 2>&1; then
        : > "$CLSACT_FLAG" 2>/dev/null
        sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG_FILE" 2>&1 || true
        echo installed
    else
        echo failed
    fi
}

clsact_remove() {
    local ifc="$1"
    [ -f "$CLSACT_FLAG" ] || return 0
    rm -f "$CLSACT_FLAG" 2>/dev/null
    clsact_artifacts || return 0
    [ -n "$ifc" ] || return 0
    clsact_ours_present "$ifc" && "$CTL" uninstall "$ifc" >> "$LOG_FILE" 2>&1
    return 0
}

clsact_wanted() {
    local ifc="$1" m
    clsact_artifacts || return 1
    m=$(guard_mode)
    case "$m" in
        on) ;;
        auto) [ -f "$CLSACT_FLAG" ] || [ "$(st_get fallback)" = 1 ] || return 1 ;;
        *) return 1 ;;
    esac
    [ -n "$ifc" ] && pref1_held_by_mirred "$ifc" && return 1
    return 0
}

HWNAT="$HNC_DIR/bin/hnc_mtk_hwnat.sh"
HWNAT_ST="n/a"
hwnat_disable() {
    [ -f "$HWNAT" ] || { echo n/a; return 0; }
    HNC_DIR="$HNC_DIR" sh "$HWNAT" disable 2>/dev/null | tail -n1
}
hwnat_restore() {
    [ -f "$HWNAT" ] && [ -f "$RUN/mtk_hwnat.state" ] && HNC_DIR="$HNC_DIR" sh "$HWNAT" restore >/dev/null 2>&1
    return 0
}

do_restore() {
    slowpath_restore
    clsact_remove "$1"
    hwnat_restore
}

tick() {
    local mode _explicit_ifc="${1:-}" ifc="${1:-}" state fb since calm sp="n/a" cl="off" detail policy_on=0 mtk_plat=0 rcode="ok" _co_rc="" _hw_rc=""
    MTK_TETHER_SUPPRESSED=0
    mode=$(guard_mode)
    [ -n "$ifc" ] || ifc=$(hotspot_iface) || ifc=""
    fb=$(st_get fallback); [ "$fb" = 1 ] || fb=0
    since=$(st_get since); case "$since" in ''|*[!0-9]*) since=0 ;; esac
    calm=$(st_get calm);   case "$calm" in ''|*[!0-9]*) calm=0 ;; esac
    has_active_policy && policy_on=1
    is_mtk_platform && mtk_plat=1

    [ -z "$_explicit_ifc" ] && [ "$mode" != on ] && [ "$policy_on" = 0 ] && hwnat_restore
    if [ "$mode" = off ]; then
        if [ "$fb" = 1 ] || [ -f "$CLSACT_FLAG" ] || [ -f "$ORIG_TETHER_FILE" ]; then
            do_restore "$ifc"
            log "mode=off: fallback restored"
        fi
        st_save 0 0 0
        write_status off "SKIPPED" 0 0 "已关闭: 不检测、不干预 offload" "n/a" "off" "$ifc" "ok"
        GUARD_LAST_MODE=off; GUARD_LAST_FB=0
        return 0
    fi

    if [ -z "$ifc" ]; then
        state="NOHOTSPOT"
    else
        state=$($CHECK_CMD 2>/dev/null | tail -n1 | tr -d ' \r\n')
        case "$state" in NOMAP|IDLE|CAPABLE|ACTIVE) ;; *) state="UNKNOWN" ;; esac
        if [ -r "$RUN/check_offload.json" ]; then
            _co_rc=$(grep -oE '"reason_code"[[:space:]]*:[[:space:]]*"[^"]*"' "$RUN/check_offload.json" 2>/dev/null | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')
        fi
    fi

    local want=0 t0_preempt=0
    if [ "$mode" = on ]; then
        [ -n "$ifc" ] && want=1
    else
        if [ "$policy_on" = 1 ] && [ "$state" = ACTIVE ]; then
            want=1
            calm=0
        elif [ "$policy_on" = 1 ] && [ "$state" = CAPABLE ]; then
            # T+0 零延迟压制: 具备 offload 能力且存在激活限速/QoS/应用策略, 不等流量跑起来直接压制!
            want=1
            t0_preempt=1
            calm=0
        elif [ "$mtk_plat" = "1" ] && [ -n "$ifc" ] && { [ "$policy_on" = 1 ] || [ -n "$_explicit_ifc" ]; }; then
            # 天玑(MTK)平台存在激活策略(或显式指定接口 apply <iface>)且热点在线时, 收敛至 want=1 压制 MDDP 旁路!
            want=1
            t0_preempt=1
            calm=0
        elif [ "$policy_on" = 1 ] && [ "${HNC_TEST_MODE:-0}" != "1" ] && [ "$state" = IDLE ] && [ -d /sys/fs/bpf/tethering ]; then
            want=1
            t0_preempt=1
            calm=0
        elif [ "$fb" = 1 ]; then
            case "$state" in
                NOHOTSPOT|NOMAP) calm=$((calm + 1)) ;;
                CAPABLE|IDLE|ACTIVE)
                    if [ "$policy_on" = 0 ]; then
                        calm=$((calm + 1))
                    else
                        calm=0
                    fi
                    ;;
                *) calm=0 ;;
            esac
            if [ "$calm" -ge "$RESTORE_AFTER" ]; then
                want=0
            else
                want=1
            fi
        fi
    fi

    if [ "$want" = 1 ]; then
        sp=$(slowpath_disable)
        [ "$mtk_plat" = "1" ] && MTK_TETHER_SUPPRESSED=1
        cl=$(clsact_apply "$ifc")
        if [ "$mode" = on ] || [ "$t0_preempt" = 1 ] || { [ "$state" = ACTIVE ] && [ "$policy_on" = 1 ]; }; then
            HWNAT_ST=$(hwnat_disable)
        fi
        if [ "$sp" = ok ] || [ "$sp" = empty ] || [ "$cl" = installed ] || [ "$HWNAT_ST" = disabled ] || [ "$MTK_TETHER_SUPPRESSED" = "1" ] || { [ "$fb" = 1 ] && [ "$calm" -gt 0 ]; }; then
            if [ "$fb" != 1 ]; then
                since=$(now_s)
            fi
            fb=1
            st_save "$fb" "$since" "$calm"
            log "fallback ON (mode=$mode offload=$state t0=$t0_preempt iface=$ifc slowpath=$sp clsact=$cl)"
        else
            fb=0; since=0; calm=0
            st_save 0 0 0
            log "fallback DEGRADED (mode=$mode offload=$state t0=$t0_preempt iface=$ifc slowpath=$sp clsact=$cl)"
        fi
        case "$sp" in
            ok)          detail="已强制 offload 走慢路径(limit_map=0, 每轮重申)" ;;
            empty)       detail="offload map 暂无条目, 下一轮重试" ;;
            unavailable) detail="hotspotd 未运行或无 hnc_ipc, 无法强制慢路径" ;;
            *)           detail="强制慢路径失败(见 hotspotd 日志)" ;;
        esac
        if [ "$mtk_plat" = "1" ] && [ "$state" = NOMAP ]; then
            detail="联发科平台无 BPF offload map, 激活策略期间已置 tether_offload_disabled=1 防 MDDP 旁路"
        fi
        [ "$mode" = auto ] && [ "$state" = ACTIVE ] && detail="检测到 offload 正在旁路限速; $detail"
        [ "$mode" = auto ] && [ "$t0_preempt" = 1 ] && [ "$state" != NOMAP ] && detail="检测到激活策略(T+0 零延迟抢占); $detail"
        [ "$cl" = skipped_pref1_mirred ] && detail="$detail; clsact 打标跳过(pref 1 为旧版 mirred)"
        case "$HWNAT_ST" in
            disabled) detail="$detail; 已关闭 MTK HWNAT" ;;
            detected_no_knob) detail="$detail; 检测到 MTK HWNAT 但无运行期开关" ;;
        esac
    else
        if [ "$fb" = 1 ]; then
            st_save 0 0 0
            do_restore "$ifc"
            log "fallback OFF (offload=$state, calm=$calm)"
        elif [ -f "$ORIG_TETHER_FILE" ]; then
            tether_hal_restore
        fi
        fb=0; since=0; calm=0; sp="n/a"; cl="off"
        case "$state" in
            NOHOTSPOT) detail="热点未开启" ;;
            NOMAP)     detail="本机无 tether offload map(非 GKI 或未启用), 无需兜底" ;;
            IDLE)      detail="offload 未在转发, 无需兜底" ;;
            CAPABLE)   detail="本机具备 offload, 当前无激活策略, 持续监测" ;;
            ACTIVE)    detail="硬件加速正常运行中(当前无激活策略, 无需慢路径压制)" ;;
            *)         detail="状态未知, 持续监测" ;;
        esac
        st_save "$fb" "$since" "$calm"
    fi

    if [ -r "$RUN/mtk_hwnat.json" ]; then
        _hw_rc=$(grep -oE '"reason_code"[[:space:]]*:[[:space:]]*"[^"]*"' "$RUN/mtk_hwnat.json" 2>/dev/null | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')
    fi
    if [ -n "$ifc" ] && is_sta_ap_same_iface "$ifc"; then
        rcode="sta_ap_same_iface"
    elif [ -z "$ifc" ] && [ -n "$SYS_NET_ERR" ]; then
        rcode="$SYS_NET_ERR"
    elif [ "$_co_rc" = "permission_denied" ] || [ "$HWNAT_ST" = "failed" ] || { [ "$HWNAT_ST" = "detected_no_knob" ] && [ "$_hw_rc" = "permission_denied" ]; }; then
        rcode="permission_denied"
    elif [ "$state" = "ACTIVE" ] && [ "$want" = "1" ]; then
        rcode="qcom_tether_bpf_active"
    elif [ "$HWNAT_ST" = "skipped_not_mtk" ] && [ "$state" = "NOMAP" ]; then
        rcode="unsupported_soc"
    elif [ "$HWNAT_ST" = "detected_no_knob" ]; then
        rcode="node_missing"
    elif [ "$state" = "NOMAP" ] && [ "$mtk_plat" = "0" ] && [ "$want" = "0" ]; then
        rcode="${_co_rc:-node_missing}"
    else
        rcode="ok"
    fi

    write_status "$mode" "$state" "$fb" "$since" "$detail" "$sp" "$cl" "$ifc" "$rcode"
    GUARD_LAST_MODE=$mode; GUARD_LAST_FB=$fb; GUARD_LAST_STATE=$state
}

guard_plan_sleep() {
    GUARD_PLAN_TOTAL=$INTERVAL
    GUARD_PLAN_WAKE=""
    [ "$GUARD_LAST_FB" = 1 ] && return 0
    [ "$GUARD_LAST_STATE" = ACTIVE ] && return 0
    hnc_act_load "$(now_s)" || return 0
    [ "$ACT_OK" = 1 ] || return 0
    case "$ACT_LEVEL" in
        hotspot_off|no_clients) ;;
        *) return 0 ;;
    esac
    [ "$IDLE_INTERVAL" -gt "$INTERVAL" ] 2>/dev/null || return 0
    GUARD_PLAN_TOTAL=$IDLE_INTERVAL
    if [ "$GUARD_LAST_MODE" = on ]; then GUARD_PLAN_WAKE=hotspot; else GUARD_PLAN_WAKE=clients; fi
}

clsact_repair() {
    local ifc="$1"
    clsact_wanted "$ifc" || { echo not_wanted; return 0; }
    [ -n "$ifc" ] || { echo unavailable; return 0; }
    case "$("$CTL" check "$ifc" 2>/dev/null)" in
        *'"ok":true'*) echo ok; return 0 ;;
    esac
    log "clsact state incomplete on $ifc, repairing"
    local r
    r=$(clsact_apply "$ifc")
    [ "$r" = installed ] && log "clsact repaired on $ifc" || log "ERROR: clsact repair on $ifc: $r"
    echo "$r"
    [ "$r" = installed ]
}

OG_LOCK="$RUN/offload_guard.lock"
_OG_LOCK_REENTRANT=0
og_lock() {
    if [ "${HNC_OFFLOAD_GUARD_LOCK_HELD:-}" = "$$" ] && [ -d "$OG_LOCK" ]; then
        _OG_LOCK_REENTRANT=1
        return 0
    fi
    mkdir -p "$RUN" 2>/dev/null
    rm -rf "$OG_LOCK".stale.* 2>/dev/null || true
    local _n=0 _max_ticks="${1:-150}" _lp _ts _now _mtime _grave
    while ! mkdir "$OG_LOCK" 2>/dev/null; do
        _lp=$(cat "$OG_LOCK/pid" 2>/dev/null)
        _ts=$(cat "$OG_LOCK/ts" 2>/dev/null)
        _now=$(now_s)
        if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
            _grave="${OG_LOCK}.stale.$$.$_now"
            if mv "$OG_LOCK" "$_grave" 2>/dev/null; then
                rm -rf "$_grave" 2>/dev/null
                continue
            fi
        elif [ -z "$_lp" ]; then
            _mtime=$(stat -c %Y "$OG_LOCK" 2>/dev/null) || _mtime=0
            if [ "$_mtime" -gt 0 ] && [ $((_now - _mtime)) -ge 5 ]; then
                _grave="${OG_LOCK}.stale.$$.$_now"
                if mv "$OG_LOCK" "$_grave" 2>/dev/null; then
                    rm -rf "$_grave" 2>/dev/null
                    continue
                fi
            fi
        fi
        case "$_ts:$_now" in
            *[!0-9:]*|:*) ;;
            *)
                if [ "$_ts" -gt 0 ] && [ $((_now - _ts)) -ge 30 ]; then
                    _grave="${OG_LOCK}.stale.$$.$_now"
                    if mv "$OG_LOCK" "$_grave" 2>/dev/null; then
                        rm -rf "$_grave" 2>/dev/null
                        continue
                    fi
                fi
                ;;
        esac
        if usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null; then
            _n=$((_n + 1))
        else
            sleep 1
            _n=$((_n + 10))
        fi
        [ "$_n" -ge "$_max_ticks" ] && return 1
    done
    echo "$$" > "$OG_LOCK/pid" 2>/dev/null
    now_s > "$OG_LOCK/ts" 2>/dev/null
    export HNC_OFFLOAD_GUARD_LOCK_HELD="$$"
    return 0
}

og_unlock() {
    if [ "${_OG_LOCK_REENTRANT:-0}" = "1" ]; then
        _OG_LOCK_REENTRANT=0
        return 0
    fi
    if [ "$(cat "$OG_LOCK/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$OG_LOCK" 2>/dev/null
        unset HNC_OFFLOAD_GUARD_LOCK_HELD
    fi
}

case "${1:-}" in
    plan)
        if ! og_lock; then
            log "WARN: offload_guard.lock busy on plan"
            echo "$INTERVAL none"
            exit 0
        fi
        trap 'og_unlock' EXIT
        trap 'og_unlock; trap - EXIT; exit 143' TERM
        trap 'og_unlock; trap - EXIT; exit 130' INT
        tick
        guard_plan_sleep
        echo "$GUARD_PLAN_TOTAL ${GUARD_PLAN_WAKE:-none}"
        ;;
    apply)
        if ! og_lock; then
            log "WARN: offload_guard.lock busy on apply"
            cat "$STATUS" 2>/dev/null
            exit 0
        fi
        trap 'og_unlock' EXIT
        trap 'og_unlock; trap - EXIT; exit 143' TERM
        trap 'og_unlock; trap - EXIT; exit 130' INT
        tick "${2:-}"
        cat "$STATUS" 2>/dev/null
        ;;
    restore)
        if ! og_lock 200; then
            log "ERROR: offload_guard.lock busy on restore"
            exit 1
        fi
        trap 'og_unlock' EXIT
        trap 'og_unlock; trap - EXIT; exit 143' TERM
        trap 'og_unlock; trap - EXIT; exit 130' INT
        _rifc=$(hotspot_iface) || _rifc=$(head -n 1 "$RUN/iface.cache" 2>/dev/null | tr -d ' \r\n')
        st_save 0 0 0
        do_restore "$_rifc"
        st_save 0 0 0
        rm -f "$STATUS" 2>/dev/null
        ;;
    mode)
        guard_mode
        ;;
    clsact_wanted)
        clsact_wanted "${2:-$(hotspot_iface)}"
        exit $?
        ;;
    clsact_repair)
        if ! og_lock; then
            log "WARN: offload_guard.lock busy on clsact_repair"
            echo busy
            exit 1
        fi
        trap 'og_unlock' EXIT
        trap 'og_unlock; trap - EXIT; exit 143' TERM
        trap 'og_unlock; trap - EXIT; exit 130' INT
        clsact_repair "${2:-$(hotspot_iface)}"
        exit $?
        ;;
    *)
        echo "usage: $0 plan|apply|restore|mode|clsact_wanted [iface]|clsact_repair [iface]" >&2
        exit 4
        ;;
esac
exit 0
