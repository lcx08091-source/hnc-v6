#!/system/bin/sh
# dpi_rebind.sh — HNC v6.1+ manual DPI capture rebind helper
# Manual DPI rebind helper.  Safe for WebUI button use: restart the dpid child,
# refresh dpi_config.json with the current hotspot iface; the C launcher (or, in
# direct mode, this script / the Go watchdog) brings dpid back up.

HNC_DIR=${HNC_DIR:-${HNC:-/data/local/hnc}}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

for _hp in "$HNC_DIR/bin/hnc_proc.sh" "${0%/*}/hnc_proc.sh"; do
    [ -f "$_hp" ] && { . "$_hp"; break; }
done
unset _hp
if ! command -v pid_matches >/dev/null 2>&1; then
    pid_matches() {
        _pm_p="$1"; _pm_kw="$2"; _pm_root="${HNC_PROC_ROOT:-/proc}"
        case "$_pm_p" in ''|*[!0-9]*) return 1 ;; esac
        [ "$_pm_p" = "$$" ] && return 1
        [ -n "${PPID:-}" ] && [ "$_pm_p" = "$PPID" ] && return 1
        [ -r "$_pm_root/$_pm_p/cmdline" ] || return 1
        if [ -r "$_pm_root/$_pm_p/comm" ]; then
            _pm_c=$(tr -d '\r\n' < "$_pm_root/$_pm_p/comm" 2>/dev/null)
            case "$_pm_c" in sh|bash|mksh|ash|dash|zsh|toybox|busybox|toolbox) return 1 ;; esac
            [ -n "$_pm_c" ] && [ "${#_pm_kw}" -le 15 ] && [ "$_pm_c" != "$_pm_kw" ] && return 1
        fi
        _pm_a0=$(tr '\000' '\n' < "$_pm_root/$_pm_p/cmdline" 2>/dev/null | head -n 1)
        [ -n "$_pm_a0" ] && [ "${_pm_a0##*/}" = "$_pm_kw" ]
    }
fi

RUN="$HNC_DIR/run"
LOG_DIR="$HNC_DIR/logs"
ETC="$HNC_DIR/etc"
LOG="$LOG_DIR/dpi_rebind.log"
CONFIG="$ETC/dpi_config.json"
RULES="$HNC_DIR/data/rules.json"
LAUNCHER_C="$HNC_DIR/bin/hnc_launcher"
DPID="$HNC_DIR/bin/hnc_dpid"

mkdir -p "$RUN" "$LOG_DIR" "$ETC" 2>/dev/null || true
log(){ echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [DPI-REBIND] $*" >> "$LOG" 2>/dev/null || true; }
json_escape(){ printf '%s' "$1" | tr '\r\n	' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }

read_pinned_override(){
    _ov=""
    if [ -f "$HNC_DIR/bin/hnc_json" ] && [ -f "$RULES" ]; then
        _ov=$(sh "$HNC_DIR/bin/hnc_json" get-top "$RULES" hotspot_iface 2>/dev/null) || _ov=""
    elif [ -f "$RULES" ]; then
        _ov=$(sed -n 's/.*"hotspot_iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RULES" 2>/dev/null | head -1)
    fi
    _ov=$(printf '%s' "$_ov" | tr -d '[:space:]"')
    case "$_ov" in ''|auto|null|-*|*..*|.|*[!A-Za-z0-9_.:-]*) _ov="" ;; esac
    printf '%s' "$_ov"
}

detect_current_iface(){
    if [ -n "$1" ] && [ "$1" != "auto" ]; then echo "$1"; return 0; fi
    if [ -f "$HNC_DIR/bin/hnc_iface.sh" ]; then
        _det=$(HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/hnc_iface.sh" get 2>/dev/null | head -1 | tr -d ' \r\n')
        [ -n "$_det" ] && { echo "$_det"; return 0; }
    fi
    if [ -f "$HNC_DIR/bin/device_detect.sh" ]; then
        _det=$(HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | head -1 | tr -d ' \r\n')
        [ -n "$_det" ] && { echo "$_det"; return 0; }
    fi
    _hint=$(head -n 1 "$RUN/hotspot_iface" 2>/dev/null | tr -d ' \r\n')
    [ -n "$_hint" ] && { echo "$_hint"; return 0; }
    _cfg=$(sed -n 's/.*"iface"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" 2>/dev/null | head -1)
    [ -n "$_cfg" ] && { echo "$_cfg"; return 0; }
    return 1
}

write_state(){
    iface=$(json_escape "$1")
    reason=$(json_escape "$2")
    now=$(date +%s 2>/dev/null || echo 0)
    _self_root=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." 2>/dev/null && pwd -P)
    _mver=""
    for _mp in "${_self_root:+$_self_root/module.prop}" "$HNC_DIR/module.prop" "/data/adb/modules/hotspot_net_ctl/module.prop"; do
        [ -n "$_mp" ] && [ -f "$_mp" ] || continue
        _mver=$(sed -n '/^version=/{s/^version=//p;q;}' "$_mp" 2>/dev/null | tr -d '\000-\037\177 "')
        [ -n "$_mver" ] && break
    done
    _mver=${_mver#v}
    _mver=$(json_escape "${_mver:-unknown}")
    _st_tmp="$RUN/dpi_state.json.tmp.$$"
    if cat > "$_st_tmp" 2>/dev/null <<EOF_STATE && [ -s "$_st_tmp" ]; then
{"schema_version":"2.0","timestamp":$now,"version":"0.5.4-rebind+${_mver}","mode":"blind","interface":"$iface","uptime_s":0,"blind_reason":"$reason","stats":{"packets":0,"dns_events":0,"tls_events":0,"kernel_drops":0,"ignored_packets":0,"parse_errors":0}}
EOF_STATE
        mv -f "$_st_tmp" "$RUN/dpi_state.json" 2>/dev/null || rm -f "$_st_tmp" 2>/dev/null || true
    else
        rm -f "$_st_tmp" 2>/dev/null || true
    fi
}

stop_dpid_graceful(){
    _proot="${HNC_PROC_ROOT:-/proc}"
    _pids=""
    p=$(cat "$RUN/dpid.pid" 2>/dev/null | tr -dc '0-9')
    if [ -n "$p" ] && pid_matches "$p" hnc_dpid && kill -0 "$p" 2>/dev/null; then
        _pids="$p"
    fi
    rm -f "$RUN/dpid.pid" 2>/dev/null || true
    if [ "$_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
        for _d in "$_proot"/[0-9]*; do
            [ -r "$_d/cmdline" ] || continue
            _p=${_d##*/}
            if pid_matches "$_p" hnc_dpid && kill -0 "$_p" 2>/dev/null; then
                case " $_pids " in *" $_p "*) ;; *) _pids="${_pids:+$_pids }$_p" ;; esac
            fi
        done
        if [ "$_proot" = "/proc" ] && command -v pidof >/dev/null 2>&1; then
            for _p in $(pidof hnc_dpid 2>/dev/null); do
                if pid_matches "$_p" hnc_dpid && kill -0 "$_p" 2>/dev/null; then
                    case " $_pids " in *" $_p "*) ;; *) _pids="${_pids:+$_pids }$_p" ;; esac
                fi
            done
        fi
    fi
    [ -n "$_pids" ] || return 0
    for _p in $_pids; do
        log "TERM hnc_dpid pid=$_p"
        kill -TERM "$_p" 2>/dev/null || kill "$_p" 2>/dev/null || true
    done
    # 轮询等待最多 2s 优雅退出, 避免直接 SIGKILL 导致 hnc_launcher 误增崩溃计数
    _use_subsec=0
    if usleep 100000 2>/dev/null; then
        _use_subsec=1
    elif sleep 0.1 2>/dev/null; then
        _use_subsec=2
    fi
    _max_ticks=20
    [ "$_use_subsec" = "0" ] && _max_ticks=2
    _tick=0
    while [ "$_tick" -lt "$_max_ticks" ]; do
        _still_alive=0
        for _p in $_pids; do
            if pid_matches "$_p" hnc_dpid && kill -0 "$_p" 2>/dev/null; then
                _still_alive=1
                break
            fi
        done
        [ "$_still_alive" = "0" ] && break
        if [ "$_tick" -gt 0 ] || [ "$_use_subsec" = "0" ]; then
            if [ "$_use_subsec" = "1" ]; then
                usleep 100000 2>/dev/null || sleep 1
            elif [ "$_use_subsec" = "2" ]; then
                sleep 0.1 2>/dev/null || sleep 1
            else
                sleep 1
            fi
        fi
        _tick=$((_tick + 1))
    done
    for _p in $_pids; do
        if pid_matches "$_p" hnc_dpid && kill -0 "$_p" 2>/dev/null; then
            log "KILL hnc_dpid pid=$_p (after 2s TERM timeout)"
            kill -9 "$_p" 2>/dev/null || true
        fi
    done
}

launcher_alive(){
    _proot="${HNC_PROC_ROOT:-/proc}"
    if command -v pidfile_live_pid >/dev/null 2>&1; then
        _gp=$(pidfile_live_pid "$RUN/dpid_guard.pid" hnc_launcher 2>/dev/null)
        [ -n "$_gp" ] && kill -0 "$_gp" 2>/dev/null && return 0
    fi
    if [ "$_proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 1
    fi
    for _d in "$_proot"/[0-9]*; do
        [ -r "$_d/cmdline" ] || continue
        _p=${_d##*/}
        if pid_matches "$_p" hnc_launcher && kill -0 "$_p" 2>/dev/null; then
            echo "$_p" > "$RUN/dpid_guard.pid" 2>/dev/null || true
            return 0
        fi
    done
    return 1
}

KEEP_CONFIG="${HNC_DPI_REBIND_KEEP_CONFIG:-0}"
if [ "${1:-}" = "--keep-config" ] || [ "${1:-}" = "--rules-reload" ]; then
    KEEP_CONFIG=1
    shift
fi
EXPLICIT_ARG="${1:-}"
if [ -n "$EXPLICIT_ARG" ] && [ "$EXPLICIT_ARG" != "auto" ]; then
    case "$EXPLICIT_ARG" in
        -*|.*|*..*)
            echo "invalid iface: $EXPLICIT_ARG" >&2
            exit 1 ;;
    esac
    if ! printf '%s' "$EXPLICIT_ARG" | grep -qE '^[A-Za-z0-9_.:-]{1,32}$'; then
        echo "invalid iface: $EXPLICIT_ARG" >&2
        exit 1
    fi
fi

LIVE_IFACE=$(detect_current_iface "$EXPLICIT_ARG")
if [ -n "$LIVE_IFACE" ]; then
    case "$LIVE_IFACE" in
        auto|-*|.*|*..*|*[!A-Za-z0-9_.:-]*) LIVE_IFACE="" ;;
    esac
fi
STATE_IFACE="${LIVE_IFACE:-auto}"

log "manual rebind requested arg='${EXPLICIT_ARG:-auto}' keep_cfg=$KEEP_CONFIG resolved='$STATE_IFACE'"
write_state "${LIVE_IFACE:-}" "manual DPI rebind requested; restarting capture (${STATE_IFACE})"

if [ -n "$LIVE_IFACE" ] && { [ -d "/sys/class/net/$LIVE_IFACE" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
    _if_tmp="$RUN/hotspot_iface.tmp.$$"
    if echo "$LIVE_IFACE" > "$_if_tmp" 2>/dev/null && [ -s "$_if_tmp" ]; then
        mv -f "$_if_tmp" "$RUN/hotspot_iface" 2>/dev/null || rm -f "$_if_tmp" 2>/dev/null || true
    else
        rm -f "$_if_tmp" 2>/dev/null || true
    fi
fi

# 规则刷新重绑(KEEP_CONFIG=1)或 auto 重绑时不覆盖 etc/dpi_config.json 已有的固定口配置
PINNED_IFACE=""
if [ "$KEEP_CONFIG" = "1" ]; then
    if [ ! -s "$CONFIG" ]; then
        _cfg_tmp="$CONFIG.tmp.$$"
        if printf '{"log_level":"info"}\n' > "$_cfg_tmp" 2>/dev/null && [ -s "$_cfg_tmp" ]; then
            mv -f "$_cfg_tmp" "$CONFIG" 2>/dev/null || rm -f "$_cfg_tmp" 2>/dev/null || true
        else
            rm -f "$_cfg_tmp" 2>/dev/null || true
        fi
    fi
else
    if [ -n "$EXPLICIT_ARG" ] && [ "$EXPLICIT_ARG" != "auto" ]; then
        PINNED_IFACE="$EXPLICIT_ARG"
    else
        PINNED_IFACE=$(read_pinned_override)
    fi

    if [ -n "$PINNED_IFACE" ]; then
        if [ -s "$CONFIG" ] && grep -q '"iface"[[:space:]]*:' "$CONFIG" 2>/dev/null; then
            _cfg_tmp="$CONFIG.tmp.$$"
            if sed 's/"iface"[[:space:]]*:[[:space:]]*"[^"]*"/"iface":"'"$PINNED_IFACE"'"/' "$CONFIG" > "$_cfg_tmp" 2>/dev/null && [ -s "$_cfg_tmp" ]; then
                mv -f "$_cfg_tmp" "$CONFIG" 2>/dev/null || rm -f "$_cfg_tmp" 2>/dev/null || true
            else
                rm -f "$_cfg_tmp" 2>/dev/null || true
            fi
        else
            _cfg_tmp="$CONFIG.tmp.$$"
            if printf '{"iface":"%s","log_level":"info"}\n' "$PINNED_IFACE" > "$_cfg_tmp" 2>/dev/null && [ -s "$_cfg_tmp" ]; then
                mv -f "$_cfg_tmp" "$CONFIG" 2>/dev/null || rm -f "$_cfg_tmp" 2>/dev/null || true
            else
                rm -f "$_cfg_tmp" 2>/dev/null || true
            fi
        fi
    elif [ ! -s "$CONFIG" ]; then
        _cfg_tmp="$CONFIG.tmp.$$"
        if printf '{"log_level":"info"}\n' > "$_cfg_tmp" 2>/dev/null && [ -s "$_cfg_tmp" ]; then
            mv -f "$_cfg_tmp" "$CONFIG" 2>/dev/null || rm -f "$_cfg_tmp" 2>/dev/null || true
        else
            rm -f "$_cfg_tmp" 2>/dev/null || true
        fi
    fi
fi
chmod 644 "$CONFIG" 2>/dev/null || true

# Clear crash flags so the launcher/dpid actually (re)start.
rm -f "$RUN/dpid_crashflag" "$RUN/dpid.crashflag" 2>/dev/null || true

# Stop old dpid via SIGTERM + up to 2s wait before SIGKILL fallback; launcher respawns it.
stop_dpid_graceful
rm -f "$RUN/dpid_crashflag" "$RUN/dpid.crashflag" 2>/dev/null || true

# Ensure a launcher is alive via /proc cmdline scan.
if launcher_alive; then
    log "C launcher alive; dpid will respawn on iface=$STATE_IFACE"
    echo "ok: rebound iface=$STATE_IFACE (C launcher respawns dpid within ~2s)"
elif [ -x "$LAUNCHER_C" ]; then
    log "starting C launcher $LAUNCHER_C"
    nohup "$LAUNCHER_C" >> "$LOG_DIR/dpid_guard.log" 2>&1 &
    echo $! > "$RUN/dpid_guard.pid"
    echo "ok: C launcher started pid=$(cat "$RUN/dpid_guard.pid" 2>/dev/null) iface=$STATE_IFACE"
elif [ -x "$DPID" ]; then
    log "no launcher; starting dpid directly"
    nohup "$DPID" -config "$CONFIG" >> "$LOG_DIR/dpid.log" 2>&1 &
    echo $! > "$RUN/dpid.pid"
    echo "ok: dpid restarted pid=$(cat "$RUN/dpid.pid" 2>/dev/null) iface=$STATE_IFACE"
else
    log "failed: hnc_dpid missing"
    echo "failed: hnc_dpid missing" >&2
    exit 1
fi
exit 0
