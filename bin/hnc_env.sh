#!/system/bin/sh
# hnc_env.sh — HNC 公共运行环境防弹衣 (v6.1+)
#
# 职责:
#   1) PATH 硬化: 仅在未设置 HNC_SKIP_PATH_HARDENING 与 HNC_TEST_MODE 时生效,
#      强制将 /system/bin 置于最前, 彻底阻断阉割版 busybox ip / tc / iptables 抢道,
#      并将各 Root 管理器目录与 /data/local/hnc/bin 放在末尾作为 applet 兜底。
#   2) hnc_ipt_wait_args: 探测并缓存 xtables 锁等待参数 (-w 2 -> -w -> 空参数 三级回退)。
#   3) hnc_provision_fallback_tools: 提前在 /data/local/hnc/bin 建立 .hnc_mc 静态副本与安全
#      applet 软链白名单(含 awk / base64 / strings / paste, 严禁软链 ip / tc / iptables)。

if [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    _he_pfx="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin"
    _he_sfx="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
    case "${PATH:-}" in
        "${_he_pfx}:"*":/data/local/hnc/bin"|"${_he_pfx}:${_he_sfx}") ;;
        "") export PATH="${_he_pfx}:${_he_sfx}" ;;
        *)  export PATH="${_he_pfx}:${PATH}:${_he_sfx}" ;;
    esac
    unset _he_pfx _he_sfx
fi

# hnc_ipt_wait_args [iptables_bin]
# 输出当前环境支持的 xtables 锁等待参数: "-w 2" / "-w" / ""
hnc_ipt_wait_args() {
    _hiw_bin="${1:-iptables}"
    if [ -n "${HNC_IPT_WAIT_OVERRIDE+1}" ]; then
        printf '%s\n' "${HNC_IPT_WAIT_OVERRIDE}"
        unset _hiw_bin
        return 0
    fi
    # 兼容 test/lib.sh mock_setup: 存在 MOCK_LOG 且未显式强制探测时不污染调用日志
    if [ -n "${MOCK_LOG:-}" ] && [ -z "${HNC_IPT_FORCE_PROBE:-}" ]; then
        printf '%s\n' "-w 2"
        unset _hiw_bin
        return 0
    fi
    _hiw_key="ipt"
    case "$_hiw_bin" in *ip6tables*) _hiw_key="ip6t" ;; esac
    if [ "$_hiw_key" = "ip6t" ] && [ "${_HNC_IP6T_WAIT_PROBED:-0}" = "1" ]; then
        printf '%s\n' "${_HNC_IP6T_WAIT_ARGS:-}"
        unset _hiw_bin _hiw_key
        return 0
    fi
    if [ "$_hiw_key" = "ipt" ] && [ "${_HNC_IPT_WAIT_PROBED:-0}" = "1" ]; then
        printf '%s\n' "${_HNC_IPT_WAIT_ARGS:-}"
        unset _hiw_bin _hiw_key
        return 0
    fi
    _hiw_run="${HNC_DIR:-${HNC:-/data/local/hnc}}/run"
    _hiw_cf="$_hiw_run/${_hiw_key}_wait.args"
    if [ -z "${HNC_IPT_FORCE_PROBE:-}" ] && [ -f "$_hiw_cf" ]; then
        _hiw_cached=$(cat "$_hiw_cf" 2>/dev/null)
        case "$_hiw_cached" in
            "-w 2"|"-w")
                if [ "$_hiw_key" = "ip6t" ]; then
                    _HNC_IP6T_WAIT_PROBED=1; _HNC_IP6T_WAIT_ARGS="$_hiw_cached"
                else
                    _HNC_IPT_WAIT_PROBED=1; _HNC_IPT_WAIT_ARGS="$_hiw_cached"
                fi
                printf '%s\n' "$_hiw_cached"
                unset _hiw_bin _hiw_key _hiw_run _hiw_cf _hiw_cached
                return 0
                ;;
            "none")
                if [ "$_hiw_key" = "ip6t" ]; then
                    _HNC_IP6T_WAIT_PROBED=1; _HNC_IP6T_WAIT_ARGS=""
                else
                    _HNC_IPT_WAIT_PROBED=1; _HNC_IPT_WAIT_ARGS=""
                fi
                printf '%s\n' ""
                unset _hiw_bin _hiw_key _hiw_run _hiw_cf _hiw_cached
                return 0
                ;;
        esac
    fi
    _hiw_res=""
    if "$_hiw_bin" -w 2 -n -L OUTPUT >/dev/null 2>&1; then
        _hiw_res="-w 2"
    elif "$_hiw_bin" -w -n -L OUTPUT >/dev/null 2>&1; then
        _hiw_res="-w"
    else
        _hiw_res=""
    fi
    if [ "$_hiw_key" = "ip6t" ]; then
        _HNC_IP6T_WAIT_PROBED=1; _HNC_IP6T_WAIT_ARGS="$_hiw_res"
    else
        _HNC_IPT_WAIT_PROBED=1; _HNC_IPT_WAIT_ARGS="$_hiw_res"
    fi
    if [ -d "$_hiw_run" ] && [ -w "$_hiw_run" ]; then
        if [ -n "$_hiw_res" ]; then
            printf '%s\n' "$_hiw_res" > "$_hiw_cf.tmp.$$" 2>/dev/null \
                && mv -f "$_hiw_cf.tmp.$$" "$_hiw_cf" 2>/dev/null || rm -f "$_hiw_cf.tmp.$$" 2>/dev/null
        else
            printf 'none\n' > "$_hiw_cf.tmp.$$" 2>/dev/null \
                && mv -f "$_hiw_cf.tmp.$$" "$_hiw_cf" 2>/dev/null || rm -f "$_hiw_cf.tmp.$$" 2>/dev/null
        fi
    fi
    printf '%s\n' "$_hiw_res"
    unset _hiw_bin _hiw_key _hiw_run _hiw_cf _hiw_res
    return 0
}

# hnc_provision_fallback_tools [hnc_dir] [mod_dir]
# 在 <hnc_dir>/bin 预置静态 multicall 副本 .hnc_mc 及白名单 applet 软链。
# 严禁将 ip / tc / iptables / ip6tables 放入软链白名单!
hnc_provision_fallback_tools() {
    _hp_hnc="${1:-${HNC_DIR:-${HNC:-/data/local/hnc}}}"
    _hp_mod="${2:-${MODDIR:-}}"
    _hp_bbdir="$_hp_hnc/bin"
    mkdir -p "$_hp_bbdir" 2>/dev/null || true
    # 防御性移除任何历史误建的危险网络命令软链(保留真实独立二进制如 hnc_tc)
    for _hp_forbid in ip tc iptables ip6tables iptables-restore ip6tables-restore; do
        [ -L "$_hp_bbdir/$_hp_forbid" ] && rm -f "$_hp_bbdir/$_hp_forbid" 2>/dev/null || true
    done
    _hp_adb="${HNC_ADB_DIR:-/data/adb}"
    _hp_ramdisk="${HNC_RAMDISK_DIR:-/debug_ramdisk}"
    _hp_mc=""
    _hp_bbl="$_hp_adb/ksu/bin/busybox $_hp_adb/ap/bin/busybox $_hp_adb/magisk/busybox $_hp_ramdisk/.magisk/busybox /debug_ramdisk/.magisk/busybox /system/xbin/busybox /system/bin/busybox"
    for _hp_cl in "${_hp_mod:+$_hp_mod/bin/hnc_compat.sh}" "$_hp_hnc/bin/hnc_compat.sh"; do
        [ -n "$_hp_cl" ] && [ -f "$_hp_cl" ] || continue
        _hp_bbx=$(HNC_COMPAT_LIB=1 . "$_hp_cl" && hnc_busybox_candidates 2>/dev/null | tr '\n' ' ')
        [ -n "$_hp_bbx" ] && _hp_bbl="$_hp_bbx $_hp_ramdisk/.magisk/busybox /debug_ramdisk/.magisk/busybox"
        break
    done
    if [ -n "${HNC_FALLBACK_BB:-}" ] && [ -x "${HNC_FALLBACK_BB}" ]; then
        _hp_mc="${HNC_FALLBACK_BB}"
    else
        for _hp_c in $_hp_bbl /system/bin/toybox; do
            [ -x "$_hp_c" ] && { _hp_mc="$_hp_c"; break; }
        done
    fi
    if [ -n "$_hp_mc" ] && cp -f "$_hp_mc" "$_hp_bbdir/.hnc_mc" 2>/dev/null; then
        chmod 755 "$_hp_bbdir/.hnc_mc" 2>/dev/null || true
        chcon u:object_r:system_file:s0 "$_hp_bbdir/.hnc_mc" 2>/dev/null || true
        _hp_al=" $("$_hp_bbdir/.hnc_mc" --list 2>/dev/null | tr '\n' ' ') "
        [ "$_hp_al" = "  " ] && _hp_al=" $("$_hp_bbdir/.hnc_mc" 2>/dev/null | tr '\n' ' ') "
        _hp_core="sleep head tail cat printf date grep sed cut tr wc"
        _hp_extra="awk rm mkdir mv touch dirname basename stat readlink sort uniq find ln chmod chown id seq pidof ps xargs nohup cp cmp ls rmdir pkill usleep od timeout base64 strings paste"
        for _hp_ap in $_hp_core $_hp_extra; do
            if [ "$_hp_al" != "  " ]; then
                case "$_hp_al" in *" $_hp_ap "*) ln -sf .hnc_mc "$_hp_bbdir/$_hp_ap" 2>/dev/null ;; esac
            else
                case " $_hp_core " in *" $_hp_ap "*) ln -sf .hnc_mc "$_hp_bbdir/$_hp_ap" 2>/dev/null ;; esac
            fi
        done
        command -v log >/dev/null 2>&1 && log "provisioned fallback applets from $_hp_mc -> $_hp_bbdir"
    fi
    if [ -x "$_hp_bbdir/.hnc_mc" ] && "$_hp_bbdir/.hnc_mc" ash -c 'exit 0' 2>/dev/null; then
        ln -sf .hnc_mc "$_hp_bbdir/sh" 2>/dev/null || true
    elif [ -e /system/bin/mksh ] && cp -fL /system/bin/mksh "$_hp_bbdir/sh" 2>/dev/null; then
        chmod 755 "$_hp_bbdir/sh" 2>/dev/null || true
    elif [ -e /system/bin/sh ] && cp -fL /system/bin/sh "$_hp_bbdir/sh" 2>/dev/null; then
        chmod 755 "$_hp_bbdir/sh" 2>/dev/null || true
    fi
    [ -e "$_hp_bbdir/sh" ] && chcon u:object_r:system_file:s0 "$_hp_bbdir/sh" 2>/dev/null || true
    unset _hp_hnc _hp_mod _hp_bbdir _hp_forbid _hp_adb _hp_ramdisk _hp_mc _hp_bbl _hp_cl _hp_bbx _hp_c _hp_al _hp_core _hp_extra _hp_ap
    return 0
}

:
