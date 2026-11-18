#!/system/bin/sh
# apply_app_qos.sh — HNC v5.37.0: 应用感知 QoS 双栈引擎(原子 --noflush 批处理 + 自动回退)

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
PLAN="$RUN/app_qos.plan"
STATE="$RUN/app_qos.state"
SIG="$RUN/app_qos.sig"
LOG="$HNC_DIR/logs/app_qos.log"
TCM="$HNC_DIR/bin/tc_manager.sh"

CHAIN=HNC_APP_QOS
CHAIN_IP=HNC_APP_QOS_IP
CHAIN_MARK=HNC_APP_QOS_MARK
TIER_MASK=0x600000
TIER_RT=0x200000
TIER_BG=0x600000
ROOT_PREF=50
INNER_PREF_FW=1
INNER_PREF_ALL=9

mkdir -p "$HNC_DIR/logs" "$RUN" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] $*" >> "$LOG" 2>/dev/null; }

class_for_mid() { if [ "$1" = "1" ]; then echo 100; else printf '%d' "$1"; fi; }
child_minor() { printf '%x' $((0xa000 + $1 * 4 + $2)); }
leaf_major() { printf '%x' $((0xb000 + $1 * 4 + $2)); }
dev_mark() { printf '0x%x' $((0x800000 + $1)); }

class_rate_ceil() {
    tc class show dev "$1" classid "1:$2" 2>/dev/null | awk -v c0="1:$2" '
        $1 == "class" && $3 == c0 { for (i = 1; i <= NF; i++) { if ($i == "rate") r = $(i+1); if ($i == "ceil") c = $(i+1) } }
        END { if (r == "") exit 1; if (c == "") c = r; print r, c }'
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
        sleep 0.1 2>/dev/null || sleep 1
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

teardown_dev() {
    local iface=$1 mid=$2 cid t dm
    cid=$(class_for_mid "$mid")
    dm=$(dev_mark "$mid")
    tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    for t in 1 2 3; do
        tc class del dev "$iface" classid "1:$(child_minor "$mid" "$t")" 2>/dev/null || true
    done
    tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$dm" fw 2>/dev/null \
        || tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
    tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "$dm" fw 2>/dev/null \
        || tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
    tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "$dm" fw 2>/dev/null \
        || tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
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

to_kbit() {
    awk -v v="$1" 'BEGIN{
        n = v + 0; u = v; sub(/^[0-9.]+/, "", u); u = tolower(u)
        if (u ~ /^g/) k = n * 1000000; else if (u ~ /^m/) k = n * 1000; else if (u ~ /^k/) k = n; else k = n / 1000
        k = int(k + 0.5); if (k < 1) k = 1; print k }'
}

build_dev() {
    local iface=$1 mid=$2 ip=$3 cid rc rate ceil rk t r p minor dm
    cid=$(class_for_mid "$mid")
    dm=$(dev_mark "$mid")
    rc=$(class_rate_ceil "$iface" "$cid")
    if [ -z "$rc" ]; then
        sh "$TCM" ensure_class "$iface" "$mid" "$ip" >/dev/null 2>&1
        rc=$(class_rate_ceil "$iface" "$cid")
        [ -z "$rc" ] && { log "skip mid=$mid: no device class 1:$cid on $iface"; return 1; }
    fi
    rate=${rc% *}; ceil=${rc#* }
    rk=$(to_kbit "$rate")
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
    tc filter del dev "$iface" parent "1:$cid" 2>/dev/null || true
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW" handle "$TIER_RT/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 1)" 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_FW" handle "$TIER_BG/$TIER_MASK" fw flowid "1:$(child_minor "$mid" 3)" 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent "1:$cid" protocol all prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null; then
        tc filter add dev "$iface" parent "1:$cid" protocol ip prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null || return 1
        tc filter add dev "$iface" parent "1:$cid" protocol ipv6 prio "$INNER_PREF_ALL" u32 match u32 0 0 flowid "1:$(child_minor "$mid" 2)" 2>/dev/null || true
    fi
    tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$dm" fw 2>/dev/null || true
    if [ -z "$HNC_TEST_MODE" ]; then
        tc filter del dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
        tc filter del dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
        tc filter del dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "$dm/0x9fffff" fw 2>/dev/null || true
    fi
    if ! tc filter add dev "$iface" parent 1: protocol all pref "$ROOT_PREF" handle "$dm/0x9fffff" fw flowid "1:$cid" 2>/dev/null; then
        tc filter add dev "$iface" parent 1: protocol ip pref "$ROOT_PREF" handle "$dm/0x9fffff" fw flowid "1:$cid" 2>/dev/null || return 1
        tc filter add dev "$iface" parent 1: protocol ipv6 pref "$ROOT_PREF" handle "$dm/0x9fffff" fw flowid "1:$cid" 2>/dev/null || true
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

ipt_build() {
    probe_ipv6
    local v4_batch="$RUN/.aq_v4_batch.$$" v6_batch="$RUN/.aq_v6_batch.$$" v6_neigh="" T _anchor_ln _save_ln
    [ "$IPV6_OK" = 1 ] && v6_neigh=$(ip -6 neigh show dev "$IFACE" 2>/dev/null | awk '
        $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {
            for (i = 2; i < NF; i++) if ($i == "lladdr") print tolower($(i+1)), tolower($1)
        }')

    awk -v iface="$IFACE" -v cm="$CHAIN_MARK" -v ch="$CHAIN" -v ci="$CHAIN_IP" \
        -v rt="$TIER_RT" -v bg="$TIER_BG" -v tmask="$TIER_MASK" \
        -v v4f="$v4_batch" -v v6f="$v6_batch" -v has6="$IPV6_OK" -v neigh="$v6_neigh" '
        BEGIN {
            if (has6 == 1 && neigh != "") {
                nn = split(neigh, lines, "\n")
                for (k = 1; k <= nn; k++) {
                    if (split(lines[k], kv, " ") == 2 && mac6_cnt[kv[1]] < 8) {
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
            dmark = sprintf("0x%x", 8388608 + mid)
            if (mac != "") {
                printf "-A %s -i %s -m mac --mac-source %s -m mark --mark 0 -j MARK --set-xmark %s/0x9fffff\n", cm, iface, mac, dmark > v4f
                if (has6 == 1)
                    printf "-A %s -i %s -m mac --mac-source %s -m mark --mark 0 -j MARK --set-xmark %s/0x9fffff\n", cm, iface, mac, dmark > v6f
            }
            printf "-A %s -m mark --mark %s/0x9fffff -g %s\n", ch, dmark, ci > v4f
            if (ip != "")
                printf "-A %s -d %s -m mark --mark 0x0/0x100000 -g %s\n", ch, ip, ci > v4f
            if (has6 == 1) {
                printf "-A %s -m mark --mark %s/0x9fffff -g %s\n", ch, dmark, ci > v6f
                for (j = 1; j <= mac6_cnt[mac]; j++)
                    printf "-A %s -d %s -m mark --mark 0x0/0x100000 -g %s\n", ch, mac6[mac, j], ci > v6f
            }
        }
        $1 == "ip" {
            bits = ($2 == "1") ? rt : (($2 == "3") ? bg : "")
            if (bits == "" || $3 == "") next
            if (index($3, ":") > 0) {
                if (has6 == 1) printf "-A %s -s %s -j MARK --set-xmark %s/%s\n", ci, $3, bits, tmask > v6f
            } else {
                printf "-A %s -s %s -j MARK --set-xmark %s/%s\n", ci, $3, bits, tmask > v4f
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
            _save_ln=$($T -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$2 == "HNC_SAVE" {print $1; exit}')
            if [ -n "$_save_ln" ]; then
                $T -t mangle -I POSTROUTING $((_save_ln + 1)) -j "$CHAIN" 2>/dev/null \
                    || $T -t mangle -A POSTROUTING -j "$CHAIN" 2>/dev/null
            else
                $T -t mangle -A POSTROUTING -j "$CHAIN" 2>/dev/null
            fi
        fi
    done
}

if [ "$1" = "teardown" ]; then
    [ -n "$2" ] && [ -n "$3" ] || exit 1
    aq_lock || exit 1
    trap 'aq_unlock' EXIT INT TERM
    teardown_dev "$2" "$3"
    cid=$(class_for_mid "$3")
    if [ -f "$STATE" ]; then
        grep -vx "$2 $cid" "$STATE" > "$STATE.tmp" 2>/dev/null || : > "$STATE.tmp"
        if [ -s "$STATE.tmp" ]; then
            mv -f "$STATE.tmp" "$STATE"
        else
            rm -f "$STATE.tmp" "$STATE" "$SIG"
            ipt_remove
            tc filter del dev "$2" parent 1: pref "$ROOT_PREF" 2>/dev/null || true
        fi
    fi
    exit 0
fi

IFACE=$(awk '$1 == "iface" { print $2; exit }' "$PLAN" 2>/dev/null)
NDEV=$(awk '$1 == "dev"' "$PLAN" 2>/dev/null | wc -l | tr -d ' ')
[ -n "$IFACE" ] || NDEV=0

if [ "${NDEV:-0}" -eq 0 ] && [ ! -f "$STATE" ]; then
    exit 0
fi

aq_lock || exit 0
trap 'aq_unlock' EXIT INT TERM
probe_ipv6

MIDS=$(awk '$1 == "dev" { print $2 }' "$PLAN" 2>/dev/null | tr '\n' ' ')
TCSIG=$(printf '%s|%s' "$IFACE" "$MIDS" | cksum | awk '{print $1 "-" $2}')
NEWSIG=$(cksum < "$PLAN" 2>/dev/null | awk '{print $1 "-" $2}')
OLD_TCSIG=$(sed -n 1p "$SIG" 2>/dev/null)
OLD_IPTSIG=$(sed -n 2p "$SIG" 2>/dev/null)
TC_OK=0
BUILD_ERR=0
if [ "${NDEV:-0}" -gt 0 ] && [ -f "$STATE" ] && [ "$OLD_TCSIG" = "$TCSIG" ]; then
    # shellcheck disable=SC2086
    children_ok "$IFACE" $MIDS && TC_OK=1
fi

if [ "$TC_OK" != 1 ]; then
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
        sh "$TCM" ensure_class "$s_if" "$s_mid" "" >/dev/null 2>&1 || true
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
            sh "$TCM" ensure_class "$IFACE" "$mid" "$ip" >/dev/null 2>&1 || true
        fi
    done < "$DEV_LIST"
    rm -f "$DEV_LIST" 2>/dev/null
fi

if [ -f "$STATE" ]; then
    if [ "$OLD_IPTSIG" != "$NEWSIG" ] \
       || ! $IPT -t mangle -C FORWARD -j "$CHAIN_MARK" 2>/dev/null \
       || ! $IPT -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null \
       || { [ "$IPV6_OK" = 1 ] && { ! $IP6T -t mangle -C FORWARD -j "$CHAIN_MARK" 2>/dev/null || ! $IP6T -t mangle -C POSTROUTING -j "$CHAIN" 2>/dev/null; }; }; then
        ipt_build
    fi
    if [ "$BUILD_ERR" = 0 ]; then
        printf '%s\n%s\n' "$TCSIG" "$NEWSIG" > "$SIG"
    else
        rm -f "$SIG" 2>/dev/null
    fi
else
    ipt_remove
    [ -n "$IFACE" ] && tc filter del dev "$IFACE" parent 1: pref "$ROOT_PREF" 2>/dev/null || true
    rm -f "$SIG"
fi
exit 0
