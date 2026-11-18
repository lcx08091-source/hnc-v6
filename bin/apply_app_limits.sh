#!/system/bin/sh
# apply_app_limits.sh — HNC v5.37.0: Dual-Stack Per-(client_mac, app_id) Downlink Rate Limiter (Atomic --noflush Batch)
#
# 核心架构:
#   1. 正交位域锚定: 在 mangle/FORWARD (HNC_APP_LIMIT_UP) 按客户端源 MAC 将槽位号 CS (1..254)
#      写入 ctmark 高 8 位 (0xff000000), 与设备级 CONNMARK_MASK (0x00ffffff) 完全正交不互踩;
#   2. 下行精准打标: 在 mangle/POSTROUTING (HNC_APP_LIMIT_DOWN, 挂于 HNC_SAVE 之后) 用二级 -g 子链
#      HNC_AL_C<slot> 对匹配的远端 IPv4 / IPv6 地址写入 0x900000+i, 不污染 ctmark[23:0];
#   3. 原子批处理提交: 内存/临时文件构造完整 *mangle 规则集后单次 iptables-restore --noflush /
#      ip6tables-restore --noflush 毫秒级切换; 若 mock 测试环境未提供对应 restore 或 --noflush 失败,
#      自动同源回退逐条 iptables/ip6tables 执行, 确保 test/run_all.sh 100% 零回归。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LIMITS_FLAT="$HNC_DIR/data/app_limits.flat"
IP_APP_FLAT="$HNC_DIR/run/ip_app_map.flat"
DEVICES="$HNC_DIR/data/devices.json"
DIRTY="$HNC_DIR/run/app_limit.dirty"
LOG="$HNC_DIR/logs/app_limits.log"

APP_SIG_FILE="$RUN/app_limits.applied.sig"
FULL_SIG_FILE="$RUN/app_limits.full_state.sig"
INACTIVE_MARKER="$RUN/app_limits_inactive.marker"
IPSTATS_FLAT="$RUN/app_limits_ipstats.flat"

APP_MARK_BASE_DEC=9437184   # 0x900000
APP_CLASS_MINOR_BASE=36864  # 0x9000
APP_CLASS_MINOR_MAX=39320   # 0x9998 (避开默认类 1:9999 = 0x9999)
CHAIN_UP=HNC_APP_LIMIT_UP
CHAIN_DOWN=HNC_APP_LIMIT_DOWN
LEGACY_CHAIN=HNC_APP_LIMIT
FILTER_PRIO=2

mkdir -p "$HNC_DIR/logs" "$RUN" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

if [ -f "$LOG" ]; then
    sz=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 262144 ] && mv "$LOG" "${LOG}.1" 2>/dev/null
fi

IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
IPV6_OK=0
if command -v "${IP6T%% *}" >/dev/null 2>&1 && $IP6T -t mangle -L -n >/dev/null 2>&1; then
    IPV6_OK=1
fi

resolve_restore_bin() {
    local base_cmd=$1 restore_name=$2 env_override=$3 custom_ipt=$4 _bin _dir
    if [ -n "$env_override" ]; then
        command -v "${env_override%% *}" >/dev/null 2>&1 && { printf '%s' "$env_override"; return 0; }
        return 1
    fi
    [ -n "$custom_ipt" ] && return 1
    _bin=$(command -v "${base_cmd%% *}" 2>/dev/null) || return 1
    case "$_bin" in
        */*)
            _dir=${_bin%/*}
            if [ -x "$_dir/$restore_name" ]; then
                printf '%s' "$_dir/$restore_name"
                return 0
            fi
            [ -n "$HNC_TEST_MODE" ] && return 1
            ;;
    esac
    [ -n "$HNC_TEST_MODE" ] && return 1
    command -v "$restore_name" 2>/dev/null || return 1
}

IPT_RESTORE_BIN=$(resolve_restore_bin "$IPT" "iptables-restore" "${HNC_IPT_RESTORE:-}" "${HNC_IPT:-}")
IP6T_RESTORE_BIN=""
[ "$IPV6_OK" = 1 ] && IP6T_RESTORE_BIN=$(resolve_restore_bin "$IP6T" "ip6tables-restore" "${HNC_IP6T_RESTORE:-}" "${HNC_IP6T:-}")

run_restore_noflush() {
    local rbin=$1 batch=$2
    [ -n "$rbin" ] && [ -s "$batch" ] || return 1
    if $rbin -w 2 --noflush < "$batch" 2>/dev/null; then
        return 0
    fi
    $rbin --noflush < "$batch" 2>/dev/null
}

AL_LOCK="$RUN/app_limits.lock"
al_lock() {
    local _n=0 _lp _ts _now
    while ! mkdir "$AL_LOCK" 2>/dev/null; do
        _lp=$(cat "$AL_LOCK/pid" 2>/dev/null)
        _ts=$(cat "$AL_LOCK/ts" 2>/dev/null)
        _now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
            rm -rf "$AL_LOCK" 2>/dev/null
            continue
        fi
        case "$_ts:$_now" in
            *[!0-9:]*|:*) ;;
            *) [ "$_ts" -gt 0 ] && [ $((_now - _ts)) -ge 30 ] && rm -rf "$AL_LOCK" 2>/dev/null && continue ;;
        esac
        _n=$((_n + 1))
        [ "$_n" -ge 50 ] && return 1
        sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$$" > "$AL_LOCK/pid" 2>/dev/null
    date +%s > "$AL_LOCK/ts" 2>/dev/null
    return 0
}
al_unlock() {
    [ "$(cat "$AL_LOCK/pid" 2>/dev/null)" = "$$" ] && rm -rf "$AL_LOCK" 2>/dev/null
}
if ! al_lock; then
    log "WARN: app_limits.lock busy, deferring to next cycle"
    exit 0
fi

HAD_DIRTY=0
if [ -f "$DIRTY" ]; then
    mv -f "$DIRTY" "${DIRTY}.processing" 2>/dev/null && HAD_DIRTY=1
fi

APP_SIG=""
tc_snapshot_if_changed() {
    prev=$(cat "$APP_SIG_FILE" 2>/dev/null)
    [ "$prev" = "$APP_SIG" ] && return 0
    printf '%s\n' "$APP_SIG" > "$APP_SIG_FILE" 2>/dev/null
    log "tc app rules changed ['$prev' -> '$APP_SIG'], refreshing tc_state snapshot"
    [ -x "$HNC_DIR/bin/tc_state_snapshot.sh" ] || return 0
    HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/tc_state_snapshot.sh" "$IFACE" >/dev/null 2>&1
    return 0
}

IFACE=""
if [ -f "$RUN/hnc_state" ]; then
    case "$(cat "$RUN/hnc_state" 2>/dev/null)" in
        ACTIVE:*) IFACE=$(sed -n 's/^ACTIVE://p' "$RUN/hnc_state" 2>/dev/null | tr -d '\r\n ') ;;
    esac
fi
[ -z "$IFACE" ] && [ -f "$RUN/active_iface" ] && IFACE=$(head -n 1 "$RUN/active_iface" 2>/dev/null | tr -d '\r\n ')
if [ -z "$IFACE" ] && [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
    IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')
fi
if [ -z "$IFACE" ]; then
    [ "$HAD_DIRTY" = 1 ] && [ ! -f "$DIRTY" ] && mv -f "${DIRTY}.processing" "$DIRTY" 2>/dev/null
    rm -f "${DIRTY}.processing" 2>/dev/null
    al_unlock
    exit 0
fi

V6_NEIGH_RAW=$(ip -6 neigh show dev "$IFACE" 2>/dev/null)
V6_NEIGH_SORTED=$(printf '%s\n' "$V6_NEIGH_RAW" | awk '
    $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {
        for (i = 2; i < NF; i++) if ($i == "lladdr") print tolower($1), tolower($(i+1))
    }' | sort)

compute_full_sig() {
    {
        printf 'iface=%s|v6=%s\n' "$IFACE" "$IPV6_OK"
        cat "$LIMITS_FLAT" 2>/dev/null
        cat "$IP_APP_FLAT" 2>/dev/null
        cat "$DEVICES" 2>/dev/null
        printf '%s\n' "$V6_NEIGH_SORTED"
    } | cksum | awk '{print $1 "-" $2}'
}

app_classes_alive() {
    local sig cids cid shown
    sig=$(cat "$APP_SIG_FILE" 2>/dev/null)
    [ -n "$sig" ] || return 0
    shown=$(tc class show dev "$IFACE" 2>/dev/null)
    [ -n "$shown" ] || return 1
    cids=$(printf '%s' "$sig" | tr ',' '\n' | sed -n 's/=.*//p')
    for cid in $cids; do
        printf '%s\n' "$shown" | grep -q "class htb $cid " || return 1
    done
    return 0
}

if [ "$HAD_DIRTY" = 0 ] && [ -s "$LIMITS_FLAT" ] && [ -s "$IP_APP_FLAT" ] && [ -f "$FULL_SIG_FILE" ]; then
    CUR_FULL_SIG=$(compute_full_sig)
    OLD_FULL_SIG=$(cat "$FULL_SIG_FILE" 2>/dev/null)
    if [ "$CUR_FULL_SIG" = "$OLD_FULL_SIG" ] \
       && $IPT -t mangle -C FORWARD -j "$CHAIN_UP" 2>/dev/null \
       && $IPT -t mangle -C POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null \
       && { [ "$IPV6_OK" = 0 ] || { $IP6T -t mangle -C FORWARD -j "$CHAIN_UP" 2>/dev/null && $IP6T -t mangle -C POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null; }; } \
       && tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb 1:" \
       && app_classes_alive; then
        al_unlock
        exit 0
    fi
fi

cleanup_ipt_app_limits() {
    local T rbin sub c _k _batch _fam _subs
    for _fam in v4 v6; do
        if [ "$_fam" = "v4" ]; then
            T="$IPT"; rbin="$IPT_RESTORE_BIN"
        else
            [ "$IPV6_OK" = 1 ] || continue
            T="$IP6T"; rbin="$IP6T_RESTORE_BIN"
        fi
        for _k in 1 2 3 4; do $T -t mangle -D FORWARD -j "$LEGACY_CHAIN" 2>/dev/null || break; done
        for _k in 1 2 3 4; do $T -t mangle -D FORWARD -j "$CHAIN_UP" 2>/dev/null || break; done
        for _k in 1 2 3 4; do $T -t mangle -D POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null || break; done
        _subs=$($T -t mangle -S 2>/dev/null | awk '/^-N HNC_AL_C[0-9]+$/{print $2}')
        if [ -n "$rbin" ]; then
            _batch="$RUN/.al_clean_${_fam}.$$"
            {
                echo "*mangle"
                for sub in "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN" $_subs; do
                    [ -n "$sub" ] && echo ":$sub - [0:0]"
                done
                for sub in $_subs "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN"; do
                    [ -n "$sub" ] && echo "-X $sub"
                done
                echo "COMMIT"
            } > "$_batch"
            if run_restore_noflush "$rbin" "$_batch"; then
                rm -f "$_batch" 2>/dev/null
                continue
            fi
            rm -f "$_batch" 2>/dev/null
        fi
        for sub in "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN"; do
            $T -t mangle -F "$sub" 2>/dev/null || true
        done
        for c in $_subs; do
            $T -t mangle -F "$c" 2>/dev/null || true
            $T -t mangle -X "$c" 2>/dev/null || true
        done
        for sub in "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN"; do
            $T -t mangle -X "$sub" 2>/dev/null || true
        done
    done
}

prune_stale_subchains() {
    local T max_slot=$1 c n _k
    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        for _k in 1 2 3 4; do $T -t mangle -D FORWARD -j "$LEGACY_CHAIN" 2>/dev/null || break; done
        $T -t mangle -F "$LEGACY_CHAIN" 2>/dev/null || true
        $T -t mangle -X "$LEGACY_CHAIN" 2>/dev/null || true
        $T -t mangle -S 2>/dev/null | awk '/^-N HNC_AL_C[0-9]+$/{print $2}' | while IFS= read -r c; do
            [ -n "$c" ] || continue
            n=${c#HNC_AL_C}
            case "$n" in ''|*[!0-9]*) continue ;; esac
            if [ "$n" -gt "$max_slot" ]; then
                $T -t mangle -F "$c" 2>/dev/null || true
                $T -t mangle -X "$c" 2>/dev/null || true
            fi
        done
    done
}

ensure_top_hooks() {
    local T _rc _anchor_ln _save_ln
    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        $T -t mangle -C FORWARD -j "$CHAIN_UP" 2>/dev/null
        _rc=$?
        if [ "$_rc" -eq 1 ]; then
            _anchor_ln=$($T -t mangle -L FORWARD -n --line-numbers 2>/dev/null | awk '$2 == "HNC_STATS" || $2 == "HNC_MARK" {ln=$1} END{if(ln) print ln}')
            if [ -n "$_anchor_ln" ]; then
                $T -t mangle -I FORWARD $((_anchor_ln + 1)) -j "$CHAIN_UP" 2>/dev/null \
                    || $T -t mangle -A FORWARD -j "$CHAIN_UP" 2>/dev/null
            else
                $T -t mangle -A FORWARD -j "$CHAIN_UP" 2>/dev/null
            fi
        fi
        $T -t mangle -C POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
        _rc=$?
        if [ "$_rc" -eq 1 ]; then
            _save_ln=$($T -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$2 == "HNC_SAVE" {print $1; exit}')
            if [ -n "$_save_ln" ]; then
                $T -t mangle -I POSTROUTING $((_save_ln + 1)) -j "$CHAIN_DOWN" 2>/dev/null \
                    || $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            else
                $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            fi
        fi
    done
}

replay_al_batch_fallback() {
    local T=$1 batch=$2 line _ch
    [ -s "$batch" ] || return 0
    while IFS= read -r line; do
        case "$line" in
            ''|'# '*'*'|'*mangle'|'COMMIT') continue ;;
            :*' - [0:0]')
                _ch=${line#:}
                _ch=${_ch%% *}
                $T -t mangle -N "$_ch" 2>/dev/null || $T -t mangle -F "$_ch" 2>/dev/null
                ;;
            -A\ *)
                set -f
                # shellcheck disable=SC2086
                set -- $line
                set +f
                $T -t mangle "$@" 2>/dev/null
                ;;
        esac
    done < "$batch"
}

reset_tc_app_limits() {
    local _p _proto cid minor_hex minor_dec
    for _p in "$FILTER_PRIO" 200 199; do
        for _proto in all ip ipv6; do
            tc filter del dev "$IFACE" parent 1: prio "$_p" protocol "$_proto" 2>/dev/null || true
        done
    done
    tc class show dev "$IFACE" 2>/dev/null | awk '/class htb 1:/ {print $3}' | \
        while IFS= read -r cid; do
            minor_hex=${cid#*:}
            minor_dec=$(printf '%d' "0x$minor_hex" 2>/dev/null)
            [ -z "$minor_dec" ] && continue
            if [ "$minor_dec" -gt "$APP_CLASS_MINOR_BASE" ] && [ "$minor_dec" -le "$APP_CLASS_MINOR_MAX" ]; then
                tc class del dev "$IFACE" classid "$cid" 2>/dev/null
            fi
        done
}

if [ ! -s "$LIMITS_FLAT" ]; then
    cleanup_ipt_app_limits
    reset_tc_app_limits
    rm -f "$INACTIVE_MARKER" "$FULL_SIG_FILE" "$IPSTATS_FLAT" "${DIRTY}.processing" 2>/dev/null
    log "no app_limits configured (cleaned old dual-stack rules)"
    tc_snapshot_if_changed
    al_unlock
    exit 0
fi

if [ ! -s "$IP_APP_FLAT" ]; then
    cleanup_ipt_app_limits
    reset_tc_app_limits
    n_cfg=$(grep -c . "$LIMITS_FLAT" 2>/dev/null)
    case "$n_cfg" in *[!0-9]*|'') n_cfg=0 ;; esac
    since=$(sed -n '1p' "$INACTIVE_MARKER" 2>/dev/null)
    case "$since" in *[!0-9]*|'') since=$(date +%s 2>/dev/null || echo 0) ;; esac
    streak=$(sed -n '2p' "$INACTIVE_MARKER" 2>/dev/null)
    case "$streak" in *[!0-9]*|'') streak=0 ;; esac
    streak=$((streak + 1))
    printf '%s\n%s\n' "$since" "$streak" > "$INACTIVE_MARKER" 2>/dev/null
    rm -f "$FULL_SIG_FILE" "${DIRTY}.processing" 2>/dev/null
    log "HNC_APP_LIMIT_INACTIVE: ip_app_map.flat empty/missing (configured=$n_cfg, streak=$streak)"
    tc_snapshot_if_changed
    al_unlock
    exit 0
fi
rm -f "$INACTIVE_MARKER" 2>/dev/null

reset_tc_app_limits

if [ -z "$HNC_TEST_MODE" ] && ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb 1:"; then
    [ -x "$HNC_DIR/bin/tc_manager.sh" ] && HNC_SKIP_TC_SNAPSHOT=1 sh "$HNC_DIR/bin/tc_manager.sh" init "$IFACE" >/dev/null 2>&1 || true
fi

DEV_MAC_IP_MAP=$(tr -d '\r\n' < "$DEVICES" 2>/dev/null | grep -oE '"[0-9A-Fa-f:]{17}"[[:space:]]*:[[:space:]]*\{[^}]*\}' | \
    sed -n 's/^"\([0-9A-Fa-f:]*\)".*"ip"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\L\1 \2/p' 2>/dev/null)
if [ -z "$DEV_MAC_IP_MAP" ] && [ -f "$DEVICES" ]; then
    DEV_MAC_IP_MAP=$(tr -d '\r\n' < "$DEVICES" 2>/dev/null | tr 'A-Z' 'a-z' | grep -oE '"[0-9a-f:]{17}"[[:space:]]*:[[:space:]]*\{[^}]*\}' | \
        sed -n 's/^"\([0-9a-f:]*\)".*"ip"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1 \2/p')
fi

resolve_mac_ip() {
    printf '%s\n' "$DEV_MAC_IP_MAP" | awk -v m="$1" '$1 == m { print $2; exit }'
}

resolve_mac_ip6s() {
    printf '%s\n' "$V6_NEIGH_SORTED" | awk -v m="$1" '$2 == m { print $1; if (++n >= 8) exit }'
}

client_online_any() {
    local mac=$1 v4=$2 v6s=$3
    [ -n "$v4" ] && return 0
    [ -n "$v6s" ] && return 0
    printf '%s\n' "$V6_NEIGH_RAW" | awk -v m="$mac" '
        tolower($0) ~ ("lladdr " m) && $NF != "FAILED" { found=1; exit }
        END { exit !found }'
}

mark_for_index() { printf '0x%x\n' $((APP_MARK_BASE_DEC + 1 + $1)); }
classid_for_index() {
    local minor=$((APP_CLASS_MINOR_BASE + 1 + $1))
    [ "$minor" -gt "$APP_CLASS_MINOR_MAX" ] && { echo ""; return; }
    printf '1:%x\n' "$minor"
}

. "$HNC_DIR/bin/tc_rate_calc.sh" 2>/dev/null || . "$(dirname "$0")/tc_rate_calc.sh"
IPNAME_JSON="$RUN/dpi_ipname.json"
IPNAME_APP_FLAT="$RUN/.ipname_app.flat.$$"
SLOT_MAP="$RUN/.al_slots.$$"
V4_HDR="$RUN/.al_v4_hdr.$$"
V4_RULES="$RUN/.al_v4_rules.$$"
V4_BATCH="$RUN/.al_v4_batch.$$"
V6_HDR="$RUN/.al_v6_hdr.$$"
V6_RULES="$RUN/.al_v6_rules.$$"
V6_BATCH="$RUN/.al_v6_batch.$$"

INCLUDE_SHARED=0
tr -d '\n' < "$HNC_DIR/data/rules.json" 2>/dev/null | \
    grep -Eq '"app_limit_include_shared_ips"[[:space:]]*:[[:space:]]*(true|"true"|1|"1"|"on")' && INCLUDE_SHARED=1

{
    echo "#sentinel -"
    tr -d '\n' < "$IPNAME_JSON" 2>/dev/null | \
        grep -oE '"[0-9A-Fa-f.:]+":\{[^{}]*\}' | \
        sed -n 's/^"\([^"]*\)":{.*"app":"\([^"]*\)".*/\1 \2/p'
} > "$IPNAME_APP_FLAT" 2>/dev/null

: > "$IPSTATS_FLAT.tmp" 2>/dev/null
: > "$SLOT_MAP" 2>/dev/null
: > "$V4_HDR"; : > "$V4_RULES"
: > "$V6_HDR"; : > "$V6_RULES"
trap 'rm -f "$IPNAME_APP_FLAT" "$IPSTATS_FLAT.tmp" "$SLOT_MAP" "$V4_HDR" "$V4_RULES" "$V4_BATCH" "$V6_HDR" "$V6_RULES" "$V6_BATCH" "${DIRTY}.processing" 2>/dev/null; al_unlock' EXIT INT TERM

split_app_ips() {
    awk -v want="$1" -v inc="$INCLUDE_SHARED" '
        FNR == NR { if ($1 !~ /^#/ && $2 != "" && $2 != want) sh[$1] = 1; next }
        $2 == want {
            if (seen[$1]++) next
            if (inc != 1 && ($1 in sh)) print "S " $1; else print "K " $1
        }' "$IPNAME_APP_FLAT" "$IP_APP_FLAT"
}

batch_top_inited=0
init_batch_top() {
    [ "$batch_top_inited" = 1 ] && return 0
    {
        echo ":$CHAIN_UP - [0:0]"
        echo ":$CHAIN_DOWN - [0:0]"
    } >> "$V4_HDR"
    echo "-A $CHAIN_DOWN ! -o $IFACE -j RETURN" >> "$V4_RULES"
    if [ "$IPV6_OK" = 1 ]; then
        {
            echo ":$CHAIN_UP - [0:0]"
            echo ":$CHAIN_DOWN - [0:0]"
        } >> "$V6_HDR"
        echo "-A $CHAIN_DOWN ! -o $IFACE -j RETURN" >> "$V6_RULES"
    fi
    batch_top_inited=1
}

next_slot=1
SUB_CHAIN=""
get_or_init_client_subchain() {
    local mac=$1 v4=$2 v6s=$3 slot cs_hex sub v6
    SUB_CHAIN=""
    slot=$(awk -v m="$mac" '$1==m{print $2; exit}' "$SLOT_MAP" 2>/dev/null)
    if [ -n "$slot" ]; then
        SUB_CHAIN="HNC_AL_C$slot"
        return 0
    fi
    [ "$next_slot" -gt 254 ] && return 1
    init_batch_top
    slot=$next_slot
    next_slot=$((next_slot + 1))
    echo "$mac $slot" >> "$SLOT_MAP"
    cs_hex=$(printf '0x%02x000000' "$slot")
    sub="HNC_AL_C$slot"

    echo ":$sub - [0:0]" >> "$V4_HDR"
    {
        echo "-A $CHAIN_UP -i $IFACE -m mac --mac-source $mac -j CONNMARK --set-xmark $cs_hex/0xff000000"
        echo "-A $CHAIN_DOWN -m connmark --mark $cs_hex/0xff000000 -g $sub"
        [ -n "$v4" ] && echo "-A $CHAIN_DOWN -d $v4 -g $sub"
    } >> "$V4_RULES"

    if [ "$IPV6_OK" = 1 ]; then
        echo ":$sub - [0:0]" >> "$V6_HDR"
        {
            echo "-A $CHAIN_UP -i $IFACE -m mac --mac-source $mac -j CONNMARK --set-xmark $cs_hex/0xff000000"
            echo "-A $CHAIN_DOWN -m connmark --mark $cs_hex/0xff000000 -g $sub"
            for v6 in $v6s; do
                echo "-A $CHAIN_DOWN -d $v6 -g $sub"
            done
        } >> "$V6_RULES"
    fi
    SUB_CHAIN="$sub"
    return 0
}

add_tc_fw_dual() {
    local mark=$1 cid=$2
    if tc filter add dev "$IFACE" protocol all parent 1: prio "$FILTER_PRIO" \
            handle "$mark" fw flowid "$cid" 2>/dev/null; then
        return 0
    fi
    tc filter add dev "$IFACE" protocol ip parent 1: prio "$FILTER_PRIO" \
        handle "$mark" fw flowid "$cid" 2>/dev/null || return 1
    if [ "$IPV6_OK" = 1 ]; then
        tc filter add dev "$IFACE" protocol ipv6 parent 1: prio 199 \
            handle "$mark" fw flowid "$cid" 2>/dev/null || return 1
    fi
    return 0
}

rollback_app_tc() {
    local mark=$1 cid=$2
    tc filter del dev "$IFACE" protocol all parent 1: prio "$FILTER_PRIO" handle "$mark" fw 2>/dev/null || true
    tc filter del dev "$IFACE" protocol ip parent 1: prio "$FILTER_PRIO" handle "$mark" fw 2>/dev/null || true
    tc filter del dev "$IFACE" protocol ipv6 parent 1: prio 199 handle "$mark" fw 2>/dev/null || true
    tc class del dev "$IFACE" classid "$cid" 2>/dev/null || true
}

i=0
applied=0
skipped=0
had_err=0
while IFS=' ' read -r MAC APP RATE _; do
    [ -z "$MAC" ] && continue
    case "$MAC" in '#'*) continue ;; esac
    MAC=$(printf '%s' "$MAC" | tr 'A-Z' 'a-z')
    case "$MAC" in
        [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
        *) skipped=$((skipped + 1)); continue ;;
    esac
    case "$RATE" in
        ''|*[!0-9.]*|.*|*.*.*) skipped=$((skipped + 1)); continue ;;
    esac

    CLIENT_IP=$(resolve_mac_ip "$MAC")
    CLIENT_IP6S=$(resolve_mac_ip6s "$MAC")
    if ! client_online_any "$MAC" "$CLIENT_IP" "$CLIENT_IP6S"; then
        log "skip $MAC/$APP: client not online (v4/v6)"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    SPLIT=$(split_app_ips "$APP")
    set -- $(printf '%s\n' "$SPLIT" | awk '
        $1 == "K" { k++ }
        $1 == "S" { s++ }
        END { printf "%d %d\n", k + s, s + 0 }')
    n_total=${1:-0}
    n_shared=${2:-0}
    APP_IPS=$(printf '%s\n' "$SPLIT" | awk '$1 == "K" { print $2 }' | sort -u)
    if [ -z "$APP_IPS" ]; then
        echo "$MAC $APP $n_total $n_shared 0" >> "$IPSTATS_FLAT.tmp"
        if [ "$n_total" -gt 0 ]; then
            log "skip $MAC/$APP: all $n_total IP(s) are shared with other apps"
        else
            log "skip $MAC/$APP: no v4/v6 IPs observed for app yet"
        fi
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    MARK=$(mark_for_index $i)
    CID=$(classid_for_index $i)
    if [ -z "$CID" ]; then
        log "skip $MAC/$APP: classid space exhausted"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi
    get_or_init_client_subchain "$MAC" "$CLIENT_IP" "$CLIENT_IP6S" || true
    if [ -z "$SUB_CHAIN" ]; then
        log "skip $MAC/$APP: client slot exhausted (>254)"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    RATE_MBIT=$(printf '%.2f' "$RATE")
    RATE_KBIT=$(awk -v v="$RATE" 'BEGIN{k=int(v*1000+0.5); if(k<1)k=1; print k}')
    APP_BURST=$(hnc_burst_k "$RATE" compat)
    APP_QUANTUM=$(hnc_quantum "$RATE")
    _cls_ok=0
    if [ -n "$APP_QUANTUM" ] && tc class add dev "$IFACE" parent 1:1 classid "$CID" htb \
        rate "${RATE_KBIT}kbit" ceil "${RATE_KBIT}kbit" \
        burst "$APP_BURST" cburst "$APP_BURST" quantum "$APP_QUANTUM" 2>/dev/null; then
        _cls_ok=1
    elif tc class add dev "$IFACE" parent 1:1 classid "$CID" htb \
        rate "${RATE_KBIT}kbit" ceil "${RATE_KBIT}kbit" \
        burst "$APP_BURST" cburst "$APP_BURST" 2>/dev/null; then
        _cls_ok=1
    fi
    if [ "$_cls_ok" != 1 ] || ! add_tc_fw_dual "$MARK" "$CID"; then
        log "ERROR: tc class/filter setup failed for $MAC/$APP (cid=$CID mark=$MARK), rolling back rule so device limit stays intact"
        rollback_app_tc "$MARK" "$CID"
        had_err=1
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    n_v4=0
    n_v6=0
    for IP in $APP_IPS; do
        case "$IP" in
            *[!0-9a-fA-F:./]*|'') continue ;;
            *:*)
                if [ "$IPV6_OK" = 1 ]; then
                    echo "-A $SUB_CHAIN -s $IP -j MARK --set-mark $MARK" >> "$V6_RULES"
                    n_v6=$((n_v6 + 1))
                fi
                ;;
            *)
                echo "-A $SUB_CHAIN -s $IP -j MARK --set-mark $MARK" >> "$V4_RULES"
                n_v4=$((n_v4 + 1))
                ;;
        esac
    done

    n_ips=$((n_v4 + n_v6))
    echo "$MAC $APP $n_total $n_shared $n_ips" >> "$IPSTATS_FLAT.tmp"
    APP_SIG="$APP_SIG$CID=$RATE_MBIT,"
    # v5.38.0: 应用限速激活时同步压制 AOSP tether BPF offload, 防止下行跳过 netfilter HNC_APPLIM 链
if [ -z "${HNC_TEST_MODE:-}" ] && [ -x "$HNC_DIR/bin/hnc_ipc" ] && [ -s "$FLAT_FILE" ]; then
    "$HNC_DIR/bin/hnc_ipc" OFFLOAD_DISABLE_GLOBAL >/dev/null 2>&1 || true
fi
log "applied $MAC (v4=${CLIENT_IP:-none}) / $APP / ${RATE_KBIT}kbit / ips=${n_ips}(v4=$n_v4,v6=$n_v6,shared_skip=$n_shared) / mark=$MARK class=$CID"
    applied=$((applied + 1))
    i=$((i + 1))
done < "$LIMITS_FLAT"

if [ "$batch_top_inited" = 1 ]; then
    used_slots=$((next_slot - 1))
    {
        echo "*mangle"
        cat "$V4_HDR"
        cat "$V4_RULES"
        echo "COMMIT"
    } > "$V4_BATCH"
    if ! run_restore_noflush "$IPT_RESTORE_BIN" "$V4_BATCH"; then
        replay_al_batch_fallback "$IPT" "$V4_BATCH"
    fi

    if [ "$IPV6_OK" = 1 ]; then
        {
            echo "*mangle"
            cat "$V6_HDR"
            cat "$V6_RULES"
            echo "COMMIT"
        } > "$V6_BATCH"
        if ! run_restore_noflush "$IP6T_RESTORE_BIN" "$V6_BATCH"; then
            replay_al_batch_fallback "$IP6T" "$V6_BATCH"
        fi
    fi

    ensure_top_hooks
    prune_stale_subchains "$used_slots"
else
    cleanup_ipt_app_limits
fi

if [ "$had_err" = 0 ]; then
    compute_full_sig > "$FULL_SIG_FILE" 2>/dev/null
else
    rm -f "$FULL_SIG_FILE" 2>/dev/null
fi

log "summary: applied=$applied skipped=$skipped err=$had_err ipv6=$IPV6_OK"
mv -f "$IPSTATS_FLAT.tmp" "$IPSTATS_FLAT" 2>/dev/null || true
rm -f "${DIRTY}.processing" 2>/dev/null
tc_snapshot_if_changed
