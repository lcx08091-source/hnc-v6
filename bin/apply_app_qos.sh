#!/system/bin/sh
# apply_app_qos.sh — HNC v6.0.0: 应用感知三档 fq_codel QoS 双栈引擎 (32位正交位域 + 单应用限速无损共存 + tc_action 协同锁)
#
# 正交契约 (T2 第 1 & 8 项):
#   - [25:24] 0x03000000: Tier 1 实时档 0x01000000/0x03000000 (prio 0, 50% rate)
#                         Tier 2 交互默认档 0x00000000/0x03000000 (prio 1, 35% rate, prio 9 u32 兜底)
#                         Tier 3 后台大流档 0x03000000/0x03000000 (prio 2, 15% rate)
#   - parent 1:<cid> 二级 fw 过滤器挂于 prio 2, 让同设备的单应用限速 app_limits (prio 1, 0xfc000000) 优先匹配;
#   - iptables 打标前判 -m mark --mark 0x0/0xfc000000, 跳过已被单应用限速打标的包;
#   - 拆除/更新时若该设备仍有 app_limits 活跃 (run/app_limits.devs), 绝不盲删 prio 1, 并在拆除 app_qos 后自动补回 1:9eXX 默认兜底子类!
#   - 五锁统一协议: 修改内核 tc 队列树期间协调获取 run/tc_action.lock (兼容 HNC_TC_LOCK_HELD 父子重入与超时防死锁)。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
RUN="$HNC_DIR/run"
PLAN="$RUN/app_qos.plan"
STATE="$RUN/app_qos.state"
AL_DEVS="$RUN/app_limits.devs"
SIG="$RUN/app_qos.sig"
LOG="$HNC_DIR/logs/app_qos.log"
TCM="$HNC_DIR/bin/tc_manager.sh"

TC_BIN=${TC_BIN:-}
if [ -z "$TC_BIN" ]; then
    if [ -z "${HNC_TEST_MODE:-}" ]; then
        for _tc in "$HNC_DIR/bin/hnc_tc" "$HNC_DIR/bin/tc" /system/bin/tc /vendor/bin/tc /system/xbin/tc; do
            [ -x "$_tc" ] && { TC_BIN="$_tc"; break; }
        done
    fi
    [ -z "$TC_BIN" ] && TC_BIN=$(command -v tc 2>/dev/null || echo tc)
fi
tc() { "$TC_BIN" "$@"; }

if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi
command -v hnc_dev_mark_hex >/dev/null 2>&1 || {
    hnc_dev_mark_hex() { printf '0x%08x\n' $(( 0x00800000 | ($1 << 16) )); }
}

CHAIN=HNC_APP_QOS
CHAIN_IP=HNC_APP_QOS_IP
CHAIN_MARK=HNC_APP_QOS_MARK
DEV_MASK="${HNC_MARK_MASK:-0x00ff0000}"
TIER_MASK="${HNC_QOS_MASK:-0x03000000}"
TIER_RT="${HNC_QOS_TIER1:-0x01000000}"
TIER_BG="${HNC_QOS_TIER3:-0x03000000}"
APPLIM_MASK="${HNC_APPLIM_MASK:-0xfc000000}"
ROOT_PREF=50
ROOT_PREF_V6=51
INNER_PREF_FW=2
INNER_PREF_FW_V6=4
INNER_PREF_ALL=9
INNER_PREF_ALL_V6=10

mkdir -p "$HNC_DIR/logs" "$RUN" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] $*" >> "$LOG" 2>/dev/null; }

class_for_mid() { if [ "$1" = "1" ]; then echo 100; else printf '%d' "$1"; fi; }
child_minor() { printf '%x' $((0xa000 + $1 * 4 + $2)); }
leaf_major() { printf '%x' $((0xb000 + $1 * 4 + $2)); }
applim_def_minor() { printf '%x' $((0x9e00 + $1)); }
dev_mark() { hnc_dev_mark_hex "$1"; }

has_applim_on_dev() {
    [ -f "$AL_DEVS" ] && grep -qx "$1 $2" "$AL_DEVS" 2>/dev/null
}

class_rate_ceil() {
    tc class show dev "$1" classid "1:$2" 2>/dev/null | awk -v c0="1:$2" '
        $1 == "class" && $3 == c0 { for (i = 1; i <= NF; i++) { if ($i == "rate") r = $(i+1); if ($i == "ceil") c = $(i+1) } }
        END { if (r == "") exit 1; if (c == "") c = r; print r, c }'
}

to_kbit() {
    awk -v v="$1" 'BEGIN{
        n = v + 0; u = v; sub(/^[0-9.]+/, "", u); u = tolower(u)
        if (u ~ /^g/) k = n * 1000000; else if (u ~ /^m/) k = n * 1000; else if (u ~ /^k/) k = n; else k = n / 1000
        k = int(k + 0.5); if (k < 1) k = 1; print k }'
}

# 当关闭某台设备的 app_qos 但该设备仍有 app_limits 时, 自动恢复 1:9eXX 兜底子类 + prio 9 过滤器, 严防逃逸至 1:9999!
restore_applim_default_child() {
    local iface=$1 mid=$2 cid rc ceil ck def_hex
    cid=$(class_for_mid "$mid")
    def_hex=$(applim_def_minor "$mid")
    rc=$(class_rate_ceil "$iface" "$cid") || rc="1000Mbit 1000Mbit"
    ceil=${rc#* }
    ck=$(to_kbit "$ceil")
    local def_rate=$((ck / 2))
    [ "$def_rate" -lt 1000 ] && def_rate=1000
    [ "$def_rate" -gt "$ck" ] && def_rate="$ck"
    tc class change dev "$iface" parent "1:$cid" classid "1:$def_hex" htb rate "${def_rate}kbit" ceil "${ck}kbit" prio 2 2>/dev/null \
        || tc class add dev "$iface" parent "1:$cid" classid "1:$def_hex" htb rate "${def_rate}kbit" ceil "${ck}kbit" prio 2 2>/dev/null || true
    tc qdisc replace dev "$iface" parent "1:$def_hex" handle "${def_hex}:" fq_codel 2>/dev/null \
        || tc qdisc replace dev "$iface" parent "1:$def_hex" handle "${def_hex}:" pfifo 2>/dev/null || true
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null \
       && ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" matchall flowid "1:$def_hex" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null \
            || tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_ALL" matchall flowid "1:$def_hex" 2>/dev/null || true
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null \
            || tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" matchall flowid "1:$def_hex" 2>/dev/null || true
    fi
}

AQ_LOCK="$RUN/app_qos.lock"
aq_lock() {
    [ "${HNC_APP_QOS_LOCK_HELD:-}" = "$$" ] && return 0
    local _n=0 _lp _ts _now
    while ! mkdir "$AQ_LOCK" 2>/dev/null; do
        _lp=$(cat "$AQ_LOCK/pid" 2>/dev/null)
        _ts=$(cat "$AQ_LOCK/ts" 2>/dev/null)
        _now=$(date +%s 2>/dev/null || echo 0)
        if [ -n "$_lp" ] && ! kill -0 "$_lp" 2>/dev/null; then
            rm -rf "$AQ_LOCK" 2>/dev/null
            continue
        fi
        case "$_ts:$_now" in
            *[!0-9:]*|:*) ;;
            *) [ "$_ts" -gt 0 ] && [ $((_now - _ts)) -ge 30 ] && rm -rf "$AQ_LOCK" 2>/dev/null && continue ;;
        esac
        _n=$((_n + 1))
        [ "$_n" -ge 50 ] && return 1
        usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1
    done
    echo "$$" > "$AQ_LOCK/pid" 2>/dev/null
    date +%s > "$AQ_LOCK/ts" 2>/dev/null
    export HNC_APP_QOS_LOCK_HELD=$$
    return 0
}
aq_unlock() {
    if [ "$(cat "$AQ_LOCK/pid" 2>/dev/null)" = "$$" ]; then
        rm -rf "$AQ_LOCK" 2>/dev/null
        unset HNC_APP_QOS_LOCK_HELD
    fi
}

# ── 五锁统一协议: 变更内核 tc 队列树前协调获取 run/tc_action.lock ──
TC_ACTION_LOCK="$RUN/tc_action.lock"
GATE_LOCK_DIR="$RUN/lock/gate"
_AQ_TC_LOCK_OWNED=0
_AQ_TC_LOCK_REENTRANT=0

_aq_gate_held_by_self() {
    [ -n "${HNC_GATE_HELD:-}" ] || return 1
    [ -d "$GATE_LOCK_DIR" ] || return 1
    [ "$(cat "$GATE_LOCK_DIR/pid" 2>/dev/null)" = "$HNC_GATE_HELD" ]
}

aq_tc_lock() {
    [ "$_AQ_TC_LOCK_OWNED" = 1 ] && return 0
    [ "$_AQ_TC_LOCK_REENTRANT" = 1 ] && return 0
    if [ -n "${HNC_TC_LOCK_HELD:-}" ] && [ -d "$TC_ACTION_LOCK" ]; then
        local _cur_pid
        _cur_pid=$(awk '{print $1}' "$TC_ACTION_LOCK/owner" 2>/dev/null)
        if [ "$_cur_pid" = "$HNC_TC_LOCK_HELD" ]; then
            _AQ_TC_LOCK_REENTRANT=1
            return 0
        fi
    fi
    rm -rf "$TC_ACTION_LOCK".stale.* 2>/dev/null || true
    local _round=0 _now _owner _opid _ots _age _reclaim _grave _gp
    while [ "$_round" -lt 40 ]; do
        if [ -d "$GATE_LOCK_DIR" ] && ! _aq_gate_held_by_self; then
            if [ "$_round" -ge 20 ]; then
                _gp=$(cat "$GATE_LOCK_DIR/pid" 2>/dev/null)
                if [ -n "$_gp" ] && ! kill -0 "$_gp" 2>/dev/null; then
                    rm -f "$GATE_LOCK_DIR/depth" "$GATE_LOCK_DIR/pid" 2>/dev/null
                    rmdir "$GATE_LOCK_DIR" 2>/dev/null || true
                fi
            fi
            _round=$((_round + 1))
            usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null || { [ "$_round" -ge 4 ] && break; sleep 1; }
            continue
        fi
        _now=$(date +%s 2>/dev/null || echo 0)
        if mkdir "$TC_ACTION_LOCK" 2>/dev/null; then
            echo "$$ app_qos $_now" > "$TC_ACTION_LOCK/owner" 2>/dev/null || true
            if [ -d "$GATE_LOCK_DIR" ] && ! _aq_gate_held_by_self; then
                rm -rf "$TC_ACTION_LOCK" 2>/dev/null || true
                _round=$((_round + 1))
                usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null || { [ "$_round" -ge 4 ] && break; sleep 1; }
                continue
            fi
            export HNC_TC_LOCK_HELD="$$"
            _AQ_TC_LOCK_OWNED=1
            return 0
        fi
        _owner=$(cat "$TC_ACTION_LOCK/owner" 2>/dev/null)
        _opid=$(printf '%s' "$_owner" | awk '{print $1}')
        _ots=$(printf '%s' "$_owner" | awk '{print $3}')
        case "$_ots" in ''|*[!0-9]*) _ots=0 ;; esac
        if [ "$_ots" -le 0 ]; then
            _ots=$(stat -c %Y "$TC_ACTION_LOCK" 2>/dev/null || echo 0)
        fi
        _age=$((_now - _ots))
        _reclaim=0
        if [ -n "$_opid" ] && kill -0 "$_opid" 2>/dev/null; then
            [ "$_age" -ge 90 ] 2>/dev/null && _reclaim=1
        else
            [ "$_age" -ge 25 ] 2>/dev/null && _reclaim=1
        fi
        if [ "$_reclaim" = 1 ]; then
            _grave="${TC_ACTION_LOCK}.stale.$$.$_now"
            if mv "$TC_ACTION_LOCK" "$_grave" 2>/dev/null; then
                rm -rf "$_grave" 2>/dev/null || true
                continue
            fi
        fi
        _round=$((_round + 1))
        usleep 100000 2>/dev/null || sleep 0.1 2>/dev/null || { [ "$_round" -ge 4 ] && break; sleep 1; }
    done
    return 1
}

aq_tc_unlock() {
    if [ "$_AQ_TC_LOCK_REENTRANT" = 1 ]; then
        _AQ_TC_LOCK_REENTRANT=0
        return 0
    fi
    [ "$_AQ_TC_LOCK_OWNED" = 1 ] || return 0
    _AQ_TC_LOCK_OWNED=0
    if [ -d "$TC_ACTION_LOCK" ]; then
        local _opid
        _opid=$(awk '{print $1}' "$TC_ACTION_LOCK/owner" 2>/dev/null)
        if [ -z "$_opid" ] || [ "$_opid" = "$$" ]; then
            rm -rf "$TC_ACTION_LOCK" 2>/dev/null || true
        fi
    fi
    unset HNC_TC_LOCK_HELD
    return 0
}

teardown_dev() {
    local iface=$1 mid=$2 cid t dm
    cid=$(class_for_mid "$mid")
    dm=$(dev_mark "$mid")
    if has_applim_on_dev "$iface" "$cid"; then
        # 该设备仍有单应用限速 prio 1/3 活跃: 仅精确拆除 prio 2/4 与 prio 9/10, 绝不误伤 prio 1/3!
        tc filter del dev "$iface" parent "1:$cid" prio "$INNER_PREF_FW" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW_V6" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" prio "$INNER_PREF_ALL" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" 2>/dev/null || true
    else
        tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    fi
    for t in 1 2 3; do
        tc class del dev "$iface" classid "1:$(child_minor "$mid" "$t")" 2>/dev/null || true
    done
    tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF_V6" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    if has_applim_on_dev "$iface" "$cid"; then
        restore_applim_default_child "$iface" "$mid"
    fi
    log "teardown $iface mid=$mid class=1:$cid"
}

children_ok() {
    local iface=$1; shift
    local all
    all=$(tc class show dev "$iface" 2>/dev/null) || return 1
    [ -n "$all" ] || return 1
    printf '%s\n' "$all" | awk -v mids="$*" '
        function kbit(v,   n, u, k) {
            n = v + 0; u = v; sub(/^[0-9.]+/, "", u); u = tolower(u)
            if (u ~ /^g/) k = n * 1000000
            else if (u ~ /^m/) k = n * 1000
            else if (u ~ /^k/) k = n
            else k = n / 1000
            k = int(k + 0.5)
            return (k < 1) ? 1 : k
        }
        $1 == "class" && $2 == "htb" {
            r = ""; c = ""
            for (i = 4; i <= NF; i++) {
                if ($i == "rate") r = $(i+1)
                if ($i == "ceil") c = $(i+1)
            }
            if (r != "") {
                if (c == "") c = r
                rate_k[$3] = kbit(r)
                ceil_k[$3] = kbit(c)
            }
        }
        END {
            n = split(mids, arr, " ")
            pct[1] = 50; pct[2] = 35; pct[3] = 15
            for (idx = 1; idx <= n; idx++) {
                mid = arr[idx] + 0
                if (mid <= 0) continue
                pcid = (mid == 1) ? "1:100" : sprintf("1:%d", mid)
                if (!(pcid in rate_k)) exit 1
                pr = rate_k[pcid]; pc = ceil_k[pcid]
                for (t = 1; t <= 3; t++) {
                    ccid = sprintf("1:%x", 40960 + mid * 4 + t)
                    if (!(ccid in rate_k)) exit 1
                    want = int(pr * pct[t] / 100)
                    if (want < 1) want = 1
                    d = rate_k[ccid] - want
                    if (d < 0) d = -d
                    if (d > want * 0.02 + 1) exit 1
                    if (ceil_k[ccid] != pc) exit 1
                }
            }
        }'
}

build_dev() {
    local iface=$1 mid=$2 ip=$3 cid rc rate ceil rk t r p minor dm def_hex
    cid=$(class_for_mid "$mid")
    dm=$(dev_mark "$mid")
    def_hex=$(applim_def_minor "$mid")
    rc=$(class_rate_ceil "$iface" "$cid")
    if [ -z "$rc" ]; then
        sh "$TCM" ensure_class "$iface" "$mid" "$ip" >/dev/null 2>&1
        rc=$(class_rate_ceil "$iface" "$cid")
        [ -z "$rc" ] && { log "skip mid=$mid: no device class 1:$cid on $iface"; return 1; }
    fi
    rate=${rc% *}; ceil=${rc#* }
    rk=$(to_kbit "$rate")

    # 若之前未挂子类, 先摘除 1:<cid> 上的直接叶子 qdisc; 若有 app_limits 1:9eXX 兜底子类, 将其替换为三档 1:a0XX
    if has_applim_on_dev "$iface" "$cid"; then
        tc filter del dev "$iface" parent "1:$cid" prio "$INNER_PREF_FW" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW_V6" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" prio "$INNER_PREF_ALL" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" 2>/dev/null || true
        tc class del dev "$iface" classid "1:$def_hex" 2>/dev/null || true
    else
        tc qdisc del dev "$iface" parent "1:$cid" 2>/dev/null || true
        tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    fi

    for t in 1 2 3; do
        case $t in 1) p=0; r=$((rk * 50 / 100)) ;; 2) p=1; r=$((rk * 35 / 100)) ;; *) p=2; r=$((rk * 15 / 100)) ;; esac
        [ "$r" -lt 1 ] && r=1
        minor=$(child_minor "$mid" "$t")
        tc class change dev "$iface" parent "1:$cid" classid "1:$minor" htb rate "${r}kbit" ceil "$ceil" prio "$p" 2>/dev/null \
            || tc class add dev "$iface" parent "1:$cid" classid "1:$minor" htb rate "${r}kbit" ceil "$ceil" prio "$p" 2>/dev/null \
            || { log "class 1:$minor add failed (mid=$mid)"; return 1; }
        tc qdisc replace dev "$iface" parent "1:$minor" handle "$(leaf_major "$mid" "$t"):" fq_codel 2>/dev/null \
            || tc qdisc replace dev "$iface" parent "1:$minor" handle "$(leaf_major "$mid" "$t"):" pfifo 2>/dev/null || true
    done

    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW_V6" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW_V6" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null \
       && ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" matchall flowid "1:$(child_minor "$mid" 2)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null \
            || tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_ALL" matchall flowid "1:$(child_minor "$mid" 2)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null \
            || tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL_V6" matchall flowid "1:$(child_minor "$mid" 2)" 2>/dev/null || true
    fi

    tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    if [ -z "$HNC_TEST_MODE" ]; then
        tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
        tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
        tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF_V6" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw flowid "1:$cid" 2>/dev/null; then
        tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
        tc filter add dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "${dm}/${DEV_MASK}" fw flowid "1:$cid" 2>/dev/null || return 1
        tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF_V6" handle "${dm}/${DEV_MASK}" fw 2>/dev/null || true
        tc filter add dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF_V6" handle "${dm}/${DEV_MASK}" fw flowid "1:$cid" 2>/dev/null || true
    fi
    log "built $iface mid=$mid class=1:$cid rate=$rate ceil=$ceil (50/35/15)"
    return 0
}

IPT=${HNC_IPT:-"iptables -w 2"}
IP6T=${HNC_IP6T:-"ip6tables -w 2"}
IPV6_OK=0
_IPV6_PROBED=0
IPT_RESTORE_BIN=""
IP6T_RESTORE_BIN=""

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

probe_ipv6() {
    [ "$_IPV6_PROBED" = 1 ] && return 0
    _IPV6_PROBED=1
    if [ -z "${HNC_IPT:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v iptables >/dev/null 2>&1; then
        iptables -w 2 -t mangle -L -n >/dev/null 2>&1 || IPT="iptables"
    fi
    if [ -z "${HNC_IP6T:-}" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v ip6tables >/dev/null 2>&1; then
        ip6tables -w 2 -t mangle -L -n >/dev/null 2>&1 || IP6T="ip6tables"
    fi
    IPT_RESTORE_BIN=$(resolve_restore_bin "$IPT" "iptables-restore" "${HNC_IPT_RESTORE:-}" "${HNC_IPT:-}")
    if command -v "${IP6T%% *}" >/dev/null 2>&1 && $IP6T -t mangle -L -n >/dev/null 2>&1; then
        IPV6_OK=1
        IP6T_RESTORE_BIN=$(resolve_restore_bin "$IP6T" "ip6tables-restore" "${HNC_IP6T_RESTORE:-}" "${HNC_IP6T:-}")
    fi
}

run_restore_noflush() {
    local rbin=$1 batch=$2
    [ -n "$rbin" ] && [ -s "$batch" ] || return 1
    if $rbin -w 2 --noflush < "$batch" 2>/dev/null; then
        return 0
    fi
    $rbin --noflush < "$batch" 2>/dev/null
}

replay_qos_batch_fallback() {
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

ipt_remove() {
    probe_ipv6
    local T rbin _i _c _batch _fam
    for _fam in v4 v6; do
        if [ "$_fam" = "v4" ]; then
            T="$IPT"; rbin="$IPT_RESTORE_BIN"
        else
            [ "$IPV6_OK" = 1 ] || continue
            T="$IP6T"; rbin="$IP6T_RESTORE_BIN"
        fi
        for _i in 1 2 3 4; do $T -t mangle -D POSTROUTING -j "$CHAIN" 2>/dev/null || break; done
        for _i in 1 2 3 4; do $T -t mangle -D FORWARD -j "$CHAIN_MARK" 2>/dev/null || break; done
        if [ -n "$rbin" ]; then
            _batch="$RUN/.aq_clean_${_fam}.$$"
            {
                echo "*mangle"
                echo ":$CHAIN - [0:0]"
                echo ":$CHAIN_IP - [0:0]"
                echo ":$CHAIN_MARK - [0:0]"
                echo "-X $CHAIN"
                echo "-X $CHAIN_IP"
                echo "-X $CHAIN_MARK"
                echo "COMMIT"
            } > "$_batch"
            if run_restore_noflush "$rbin" "$_batch"; then
                rm -f "$_batch" 2>/dev/null
                continue
            fi
            rm -f "$_batch" 2>/dev/null
        fi
        for _c in "$CHAIN" "$CHAIN_IP" "$CHAIN_MARK"; do
            $T -t mangle -F "$_c" 2>/dev/null
            $T -t mangle -X "$_c" 2>/dev/null
        done
    done
    return 0
}

heal_postrouting_before_save() {
    local _cmd="$1" _ch="$2" _del_n _k _save_ln
    [ -n "$_cmd" ] || return 0
    _del_n=$($_cmd -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk -v ch="$_ch" '
        $1 ~ /^[0-9]+$/ {
            ln = $1 + 0
            if ($2 == "HNC_SAVE" && save_ln == 0) save_ln = ln
            if ($2 == ch) { cnt++; max_ch = ln }
        }
        END {
            if (cnt > 0 && save_ln > 0 && (max_ch > save_ln || cnt > 1)) printf "%d\n", cnt
        }
    ')
    [ -n "$_del_n" ] || return 0
    _k=0
    while [ "$_k" -lt "$_del_n" ]; do
        $_cmd -t mangle -D POSTROUTING -j "$_ch" 2>/dev/null || break
        _k=$((_k + 1))
    done
    _save_ln=$($_cmd -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2 == "HNC_SAVE" {print $1; exit}')
    if [ -n "$_save_ln" ]; then
        $_cmd -t mangle -I POSTROUTING "$_save_ln" -j "$_ch" 2>/dev/null \
            || $_cmd -t mangle -A POSTROUTING -j "$_ch" 2>/dev/null
    else
        $_cmd -t mangle -A POSTROUTING -j "$_ch" 2>/dev/null
    fi
}

ipt_build() {
    probe_ipv6
    local v4_batch="$RUN/.aq_v4_batch.$$" v6_batch="$RUN/.aq_v6_batch.$$" v6_neigh="" _n6_raw="" T _anchor_ln _save_ln
    if [ "$IPV6_OK" = 1 ]; then
        if ! _n6_raw=$(ip -6 neigh show dev "$IFACE" 2>/dev/null) || { [ -z "$_n6_raw" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
            _n6_raw=$(ip neigh show dev "$IFACE" 2>/dev/null)
        fi
        v6_neigh=$(printf '%s\n' "$_n6_raw" | awk '
            $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {
                for (i = 2; i < NF; i++) if ($i == "lladdr") print tolower($(i+1)), tolower($1)
            }' | tr -d '\r' | tr '\n' ';')
    fi

    awk -v iface="$IFACE" -v cm="$CHAIN_MARK" -v ch="$CHAIN" -v ci="$CHAIN_IP" \
        -v dmask="$DEV_MASK" -v amask="$APPLIM_MASK" -v rt="$TIER_RT" -v bg="$TIER_BG" -v tmask="$TIER_MASK" \
        -v v4f="$v4_batch" -v v6f="$v6_batch" -v has6="$IPV6_OK" -v neigh="$v6_neigh" '
        BEGIN {
            if (has6 == 1 && neigh != "") {
                nn = split(neigh, arr, ";")
                for (k = 1; k <= nn; k++) {
                    if (split(arr[k], kv, " ") == 2 && mac6_cnt[kv[1]] < 8) {
                        mac6_cnt[kv[1]]++
                        mac6[kv[1], mac6_cnt[kv[1]]] = kv[2]
                    }
                }
            }
            print "*mangle" > v4f
            printf ":%s - [0:0]\n:%s - [0:0]\n:%s - [0:0]\n", cm, ch, ci > v4f
            printf "-A %s ! -o %s -j RETURN\n", ch, iface > v4f
            if (has6 == 1) {
                print "*mangle" > v6f
                printf ":%s - [0:0]\n:%s - [0:0]\n:%s - [0:0]\n", cm, ch, ci > v6f
                printf "-A %s ! -o %s -j RETURN\n", ch, iface > v6f
            }
        }
        $1 == "dev" {
            mid = $2 + 0; mac = tolower($3); ip = $4
            dmark = sprintf("0x%08x", 8388608 + mid * 65536)
            if (mac != "") {
                printf "-A %s -i %s -m mac --mac-source %s -m mark --mark 0x0/%s -j MARK --set-xmark %s/%s\n", cm, iface, mac, dmask, dmark, dmask > v4f
                if (has6 == 1)
                    printf "-A %s -i %s -m mac --mac-source %s -m mark --mark 0x0/%s -j MARK --set-xmark %s/%s\n", cm, iface, mac, dmask, dmark, dmask > v6f
            }
            printf "-A %s -m mark --mark %s/%s -g %s\n", ch, dmark, dmask, ci > v4f
            if (ip != "")
                printf "-A %s -d %s -m mark --mark 0x0/%s -g %s\n", ch, ip, amask, ci > v4f
            if (has6 == 1) {
                printf "-A %s -m mark --mark %s/%s -g %s\n", ch, dmark, dmask, ci > v6f
                for (j = 1; j <= mac6_cnt[mac]; j++)
                    printf "-A %s -d %s -m mark --mark 0x0/%s -g %s\n", ch, mac6[mac, j], amask, ci > v6f
            }
        }
        $1 == "ip" {
            bits = ($2 == "1") ? rt : (($2 == "3") ? bg : "")
            if (bits == "" || $3 == "") next
            # 跳过已被单应用限速打标的包 (-m mark --mark 0x0/0xfc000000), 每条规则仅一个 -m mark
            if (index($3, ":") > 0) {
                if (has6 == 1) printf "-A %s -s %s -m mark --mark 0x0/%s -j MARK --set-xmark %s/%s\n", ci, $3, amask, bits, tmask > v6f
            } else {
                printf "-A %s -s %s -m mark --mark 0x0/%s -j MARK --set-xmark %s/%s\n", ci, $3, amask, bits, tmask > v4f
            }
        }
        END {
            print "COMMIT" > v4f
            close(v4f)
            if (has6 == 1) {
                print "COMMIT" > v6f
                close(v6f)
            }
        }
    ' "$PLAN"

    if ! run_restore_noflush "$IPT_RESTORE_BIN" "$v4_batch"; then
        replay_qos_batch_fallback "$IPT" "$v4_batch"
    fi
    if [ "$IPV6_OK" = 1 ]; then
        if ! run_restore_noflush "$IP6T_RESTORE_BIN" "$v6_batch"; then
            replay_qos_batch_fallback "$IP6T" "$v6_batch"
        fi
    fi
    rm -f "$v4_batch" "$v6_batch" 2>/dev/null

    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        if ! $T -t mangle -C FORWARD -j "$CHAIN_MARK" 2>/dev/null; then
            _anchor_ln=$($T -t mangle -L FORWARD -n --line-numbers 2>/dev/null | awk '$2 == "HNC_STATS" || $2 == "HNC_MARK" {ln=$1} END{if(ln) print ln}')
            if [ -n "$_anchor_ln" ]; then
                $T -t mangle -I FORWARD $((_anchor_ln + 1)) -j "$CHAIN_MARK" 2>/dev/null \
                    || $T -t mangle -A FORWARD -j "$CHAIN_MARK" 2>/dev/null
            else
                $T -t mangle -A FORWARD -j "$CHAIN_MARK" 2>/dev/null
            fi
        fi
        if ! $T -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null; then
            # v5.40.2: 插入到 HNC_SAVE 之前, 避免尾部 HNC_EGRESS_FIX (--nfmask 0xffff0000) 覆盖清零 [25:24] 应用 QoS 档位
            _save_ln=$($T -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$1 ~ /^[0-9]+$/ && $2 == "HNC_SAVE" {print $1; exit}')
            if [ -n "$_save_ln" ]; then
                $T -t mangle -I POSTROUTING "$_save_ln" -j "$CHAIN" 2>/dev/null \
                    || $T -t mangle -A POSTROUTING -j "$CHAIN" 2>/dev/null
            else
                $T -t mangle -A POSTROUTING -j "$CHAIN" 2>/dev/null
            fi
        else
            heal_postrouting_before_save "$T" "$CHAIN"
        fi
    done
}

_aq_hash_stream() {
    if command -v cksum >/dev/null 2>&1; then
        cksum | awk 'NF>=2 && $1!="" {print $1 "-" $2}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk 'NF>=1 && $1!="" {print $1}'
    elif command -v md5sum >/dev/null 2>&1; then
        md5sum | awk 'NF>=1 && $1!="" {print $1}'
    else
        wc -c | awk 'NF>=1 && $1~/^[0-9]+$/ {print "wc-" $1}'
    fi
}

if [ "$1" = "teardown" ]; then
    [ -n "$2" ] && [ -n "$3" ] || exit 1
    aq_lock || exit 1
    trap 'aq_tc_unlock; aq_unlock' EXIT
    trap 'aq_tc_unlock; aq_unlock; trap - EXIT; exit 143' TERM
    trap 'aq_tc_unlock; aq_unlock; trap - EXIT; exit 130' INT
    aq_tc_lock || { log "WARN: tc_action.lock busy on teardown $2 $3"; exit 1; }
    teardown_dev "$2" "$3"
    cid=$(class_for_mid "$3")
    _need_ipt_rm=0
    if [ -f "$STATE" ]; then
        grep -vx "$2 $cid" "$STATE" > "$STATE.tmp" 2>/dev/null || : > "$STATE.tmp"
        if [ -s "$STATE.tmp" ]; then
            mv -f "$STATE.tmp" "$STATE"
        else
            rm -f "$STATE.tmp" "$STATE" "$SIG"
            tc filter del dev "$2" parent 1: pref "$ROOT_PREF" 2>/dev/null || true
            tc filter del dev "$2" parent 1: pref "$ROOT_PREF_V6" 2>/dev/null || true
            _need_ipt_rm=1
        fi
    fi
    if [ "${HNC_SKIP_ENSURE_CLASS:-0}" != "1" ] && ! has_applim_on_dev "$2" "$cid"; then
        sh "$TCM" ensure_class "$2" "$3" >/dev/null 2>&1 || true
    fi
    aq_tc_unlock
    [ "$_need_ipt_rm" = 1 ] && ipt_remove
    exit 0
fi

IFACE=$(awk '$1 == "iface" { print $2; exit }' "$PLAN" 2>/dev/null)
NDEV=$(awk '$1 == "dev"' "$PLAN" 2>/dev/null | wc -l | tr -d ' ')
[ -n "$IFACE" ] || NDEV=0

if [ "${NDEV:-0}" -eq 0 ] && [ ! -f "$STATE" ]; then
    exit 0
fi

aq_lock || exit 0
trap 'aq_tc_unlock; aq_unlock' EXIT
trap 'aq_tc_unlock; aq_unlock; trap - EXIT; exit 143' TERM
trap 'aq_tc_unlock; aq_unlock; trap - EXIT; exit 130' INT
probe_ipv6

MIDS=$(awk '$1 == "dev" { print $2 }' "$PLAN" 2>/dev/null | tr '\n' ' ')
TCSIG=$(printf '%s|%s' "$IFACE" "$MIDS" | _aq_hash_stream)
NEWSIG=$(_aq_hash_stream < "$PLAN" 2>/dev/null)
OLD_TCSIG=$(sed -n 1p "$SIG" 2>/dev/null)
OLD_IPTSIG=$(sed -n 2p "$SIG" 2>/dev/null)
TC_OK=0
BUILD_ERR=0
if [ "${NDEV:-0}" -gt 0 ] && [ -f "$STATE" ] && [ -n "$TCSIG" ] && [ "$OLD_TCSIG" = "$TCSIG" ]; then
    # shellcheck disable=SC2086
    children_ok "$IFACE" $MIDS && TC_OK=1
fi

if [ "$TC_OK" != 1 ]; then
    if ! aq_tc_lock; then
        log "WARN: tc_action.lock busy, deferring app_qos tc rebuild"
        exit 0
    fi
    OLD_STATE=$(cat "$STATE" 2>/dev/null)
    : > "$STATE.tmp"
    awk '$1 == "dev" { print $2 }' "$PLAN" 2>/dev/null | while read -r mid; do
        case "$mid" in ''|*[!0-9]*) continue ;; esac
        echo "$IFACE $(class_for_mid "$mid")" >> "$STATE.tmp"
    done
    if [ -s "$STATE.tmp" ]; then
        mv -f "$STATE.tmp" "$STATE"
    else
        rm -f "$STATE.tmp" "$STATE"
    fi

    printf '%s\n' "$OLD_STATE" | while read -r s_if s_cid; do
        [ -n "$s_if" ] || continue
        grep -qx "$s_if $s_cid" "$STATE" 2>/dev/null && continue
        s_mid=$s_cid; [ "$s_cid" = "100" ] && s_mid=1
        teardown_dev "$s_if" "$s_mid"
        if ! has_applim_on_dev "$s_if" "$s_cid"; then
            sh "$TCM" ensure_class "$s_if" "$s_mid" "" >/dev/null 2>&1 || true
        fi
    done

    DEV_LIST="$RUN/.aq_devs.$$"
    awk '$1 == "dev" { print $2, $4 }' "$PLAN" 2>/dev/null > "$DEV_LIST"
    while read -r mid ip; do
        case "$mid" in ''|*[!0-9]*) continue ;; esac
        if ! build_dev "$IFACE" "$mid" "$ip"; then
            BUILD_ERR=1
            cid=$(class_for_mid "$mid")
            log "ERROR: build_dev failed for $IFACE mid=$mid, rolling back partial QoS subtree"
            teardown_dev "$IFACE" "$mid"
            if [ -f "$STATE" ]; then
                grep -vx "$IFACE $cid" "$STATE" > "$STATE.tmp" 2>/dev/null || : > "$STATE.tmp"
                if [ -s "$STATE.tmp" ]; then mv -f "$STATE.tmp" "$STATE"; else rm -f "$STATE.tmp" "$STATE"; fi
            fi
            if ! has_applim_on_dev "$IFACE" "$cid"; then
                sh "$TCM" ensure_class "$IFACE" "$mid" "$ip" >/dev/null 2>&1 || true
            fi
        fi
    done < "$DEV_LIST"
    rm -f "$DEV_LIST" 2>/dev/null
    aq_tc_unlock
fi

if [ -f "$STATE" ]; then
    if [ -z "$NEWSIG" ] || [ "$OLD_IPTSIG" != "$NEWSIG" ] \
       || ! $IPT -t mangle -C FORWARD -j "$CHAIN_MARK" 2>/dev/null \
       || ! $IPT -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null \
       || { [ "$IPV6_OK" = 1 ] && { ! $IP6T -t mangle -C FORWARD -j "$CHAIN_MARK" 2>/dev/null || ! $IP6T -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null; }; }; then
        ipt_build
    else
        heal_postrouting_before_save "$IPT" "$CHAIN"
        [ "$IPV6_OK" = 1 ] && heal_postrouting_before_save "$IP6T" "$CHAIN"
    fi
    if [ "$BUILD_ERR" = 0 ] && [ -n "$TCSIG" ] && [ -n "$NEWSIG" ]; then
        printf '%s\n%s\n' "$TCSIG" "$NEWSIG" > "$SIG"
    else
        rm -f "$SIG" 2>/dev/null
    fi
else
    ipt_remove
    if [ -n "$IFACE" ]; then
        if aq_tc_lock; then
            tc filter del dev "$IFACE" parent 1: pref "$ROOT_PREF" 2>/dev/null || true
            tc filter del dev "$IFACE" parent 1: pref "$ROOT_PREF_V6" 2>/dev/null || true
            aq_tc_unlock
        fi
    fi
    rm -f "$SIG"
fi
exit 0
