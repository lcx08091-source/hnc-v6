#!/system/bin/sh
# apply_app_limits.sh — HNC v5.34: Dual-Stack (IPv4 + IPv6) Per-(client_mac, app_id) Downlink Rate Limiter
#
# v5.34 双栈核心架构:
#   1. 正交位域锚定: 在 mangle/FORWARD (HNC_APP_LIMIT_UP) 按客户端源 MAC 将槽位号 CS (1..254)
#      写入 ctmark 高 8 位 (0xff000000), 与设备级 CONNMARK_MASK (0x00ffffff) 完全正交不互踩;
#   2. 下行精准打标: 在 mangle/POSTROUTING (HNC_APP_LIMIT_DOWN, 挂于 HNC_SAVE 之后) 用二级 -g 子链
#      HNC_AL_C<slot> (connmark 高 8 位主路径 + ip -6 neigh 活跃全球单播地址双保险) 对匹配的远端
#      IPv4 / IPv6 应用地址写入 0x900000+i, 绝不污染 ctmark[23:0] 的设备级 0x800000+mid;
#   3. 双栈 tc 过滤器: 使用 protocol all prio 2 fw (兼容回退拆分 protocol ip + ipv6), 让携带
#      0x900000+i 的 IPv4 (0x0800) 与 IPv6 (0x86dd) 下行包同时进入对应 HTB 限速类;
#   4. 摘要快路径与原子脏标: 配置与 IP 映射无变化且链/类完好时跳过拆建, 消除每 30 秒令牌桶重置。

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

APP_MARK_BASE_DEC=9437184   # 0x900000
APP_CLASS_MINOR_BASE=36864  # 0x9000
APP_CLASS_MINOR_MAX=39320   # 0x9998 (避开默认类 1:9999 = 0x9999)
CHAIN_UP=HNC_APP_LIMIT_UP
CHAIN_DOWN=HNC_APP_LIMIT_DOWN
LEGACY_CHAIN=HNC_APP_LIMIT
FILTER_PRIO=2               # 高于设备级 u32 与 v6_sync (201..299), 防设备级过滤器抢走应用限速包

mkdir -p "$HNC_DIR/logs" "$RUN" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

if [ -f "$LOG" ]; then
    sz=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    [ "$sz" -gt 262144 ] && mv "$LOG" "${LOG}.1" 2>/dev/null
fi

IPT="iptables -w 2"
IP6T="ip6tables -w 2"
IPV6_OK=0
if command -v ip6tables >/dev/null 2>&1 && $IP6T -t mangle -L -n >/dev/null 2>&1; then
    IPV6_OK=1
fi

# 互斥锁: 防止 hnc_watchdog(30s 周期)与 hnc_httpd(保存应用限速即时触发)并发拆建链与 HTB 类
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
[ -f "$HNC_DIR/run/active_iface" ] && IFACE=$(head -n 1 "$HNC_DIR/run/active_iface" 2>/dev/null | tr -d '\r\n ')
if [ -z "$IFACE" ] && [ -x "$HNC_DIR/bin/device_detect.sh" ]; then
    IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')
fi
if [ -z "$IFACE" ]; then
    [ "$HAD_DIRTY" = 1 ] && [ ! -f "$DIRTY" ] && mv -f "${DIRTY}.processing" "$DIRTY" 2>/dev/null
    rm -f "${DIRTY}.processing" 2>/dev/null
    al_unlock
    exit 0
fi

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

# 无变更摘要快路径: 同时校验双栈 FORWARD(UP) + POSTROUTING(DOWN) 跳转链与全部 1:900x HTB 子类均在位
if [ "$HAD_DIRTY" = 0 ] && [ -s "$LIMITS_FLAT" ] && [ -s "$IP_APP_FLAT" ] && [ -f "$FULL_SIG_FILE" ]; then
    CUR_FULL_SIG=$(
        {
            printf 'iface=%s|v6=%s\n' "$IFACE" "$IPV6_OK"
            cat "$LIMITS_FLAT" 2>/dev/null
            cat "$IP_APP_FLAT" 2>/dev/null
            cat "$DEVICES" 2>/dev/null
            ip -6 neigh show dev "$IFACE" 2>/dev/null | awk '$1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {for(i=2;i<NF;i++) if($i=="lladdr") print tolower($1), tolower($(i+1))}' | sort
        } | cksum | awk '{print $1 "-" $2}'
    )
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
    local T sub c _k
    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        for _k in 1 2 3 4; do $T -t mangle -D FORWARD -j "$LEGACY_CHAIN" 2>/dev/null || break; done
        for _k in 1 2 3 4; do $T -t mangle -D FORWARD -j "$CHAIN_UP" 2>/dev/null || break; done
        for _k in 1 2 3 4; do $T -t mangle -D POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null || break; done
        for sub in "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN"; do
            $T -t mangle -F "$sub" 2>/dev/null || true
        done
        $T -t mangle -S 2>/dev/null | awk '/^-N HNC_AL_C[0-9]+$/{print $2}' | while IFS= read -r c; do
            [ -n "$c" ] || continue
            $T -t mangle -F "$c" 2>/dev/null || true
            $T -t mangle -X "$c" 2>/dev/null || true
        done
        for sub in "$LEGACY_CHAIN" "$CHAIN_UP" "$CHAIN_DOWN"; do
            $T -t mangle -X "$sub" 2>/dev/null || true
        done
    done
}

# ─── Step 1: Clean old app-limit chains, filters & HTB classes ─────────
cleanup_ipt_app_limits

for _p in "$FILTER_PRIO" 200 199; do
    for _proto in all ip ipv6; do
        tc filter del dev "$IFACE" parent 1: prio "$_p" protocol "$_proto" 2>/dev/null || true
    done
done

tc class show dev "$IFACE" 2>/dev/null | awk '/class htb 1:/ {print $3}' | \
    while IFS= read -r cid; do
        minor_hex=$(echo "$cid" | awk -F: '{print $2}')
        minor_dec=$(printf '%d' "0x$minor_hex" 2>/dev/null)
        [ -z "$minor_dec" ] && continue
        if [ "$minor_dec" -gt "$APP_CLASS_MINOR_BASE" ] && [ "$minor_dec" -le "$APP_CLASS_MINOR_MAX" ]; then
            tc class del dev "$IFACE" classid "$cid" 2>/dev/null
        fi
    done

# ─── Step 2: Check active config & map readiness ───────────────────────
if [ ! -s "$LIMITS_FLAT" ]; then
    rm -f "$INACTIVE_MARKER" "$FULL_SIG_FILE" "$IPSTATS_FLAT" "${DIRTY}.processing" 2>/dev/null
    log "no app_limits configured (cleaned old dual-stack rules)"
    tc_snapshot_if_changed
    al_unlock
    exit 0
fi

if [ ! -s "$IP_APP_FLAT" ]; then
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

# Ensure root HTB 1: exists on $IFACE (pass HNC_SKIP_TC_SNAPSHOT=1 so BUG-012 conditional snapshot stays controlled here)
if [ -z "$HNC_TEST_MODE" ] && ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb 1:"; then
    [ -x "$HNC_DIR/bin/tc_manager.sh" ] && HNC_SKIP_TC_SNAPSHOT=1 sh "$HNC_DIR/bin/tc_manager.sh" init "$IFACE" >/dev/null 2>&1 || true
fi

resolve_mac_ip() {
    local mac_lc
    mac_lc=$(echo "$1" | tr 'A-Z' 'a-z')
    [ -f "$DEVICES" ] || return 1
    tr -d '\r\n' < "$DEVICES" 2>/dev/null \
        | grep -oiE "\"$mac_lc\"[[:space:]]*:[[:space:]]*\{[^}]*\}" \
        | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1/p' | head -n 1
}

resolve_mac_ip6s() {
    local mac_lc
    mac_lc=$(echo "$1" | tr 'A-Z' 'a-z')
    ip -6 neigh show dev "$IFACE" 2>/dev/null | awk -v m="$mac_lc" '
        $1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {
            for (i = 2; i < NF; i++) {
                if ($i == "lladdr" && tolower($(i+1)) == m) {
                    print tolower($1)
                    if (++n >= 8) exit
                }
            }
        }'
}

client_online_any() {
    local mac=$1 v4=$2 v6s=$3 mac_lc
    [ -n "$v4" ] && return 0
    [ -n "$v6s" ] && return 0
    mac_lc=$(echo "$mac" | tr 'A-Z' 'a-z')
    ip -6 neigh show dev "$IFACE" 2>/dev/null | awk -v m="$mac_lc" '
        tolower($0) ~ ("lladdr " m) && $NF != "FAILED" { found=1; exit }
        END { exit !found }'
}

mark_for_index() {
    echo "0x$(printf '%x' $((APP_MARK_BASE_DEC + 1 + $1)))"
}

classid_for_index() {
    local minor=$((APP_CLASS_MINOR_BASE + 1 + $1))
    if [ "$minor" -gt "$APP_CLASS_MINOR_MAX" ]; then
        echo ""
        return
    fi
    echo "1:$(printf '%x' $minor)"
}

. "$HNC_DIR/bin/tc_rate_calc.sh" 2>/dev/null || . "$(dirname "$0")/tc_rate_calc.sh"
IPNAME_JSON="$RUN/dpi_ipname.json"
IPNAME_APP_FLAT="$RUN/.ipname_app.flat.$$"
IPSTATS_FLAT="$RUN/app_limits_ipstats.flat"
SLOT_MAP="$RUN/.al_slots.$$"
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
trap 'rm -f "$IPNAME_APP_FLAT" "$IPSTATS_FLAT.tmp" "$SLOT_MAP" "${DIRTY}.processing" 2>/dev/null; al_unlock' EXIT INT TERM

split_app_ips() {
    awk -v want="$1" -v inc="$INCLUDE_SHARED" '
        FNR == NR { if ($1 !~ /^#/ && $2 != "" && $2 != want) sh[$1] = 1; next }
        $2 == want {
            if (seen[$1]++) next
            if (inc != 1 && ($1 in sh)) print "S " $1; else print "K " $1
        }' "$IPNAME_APP_FLAT" "$IP_APP_FLAT"
}

chains_ready=0
ensure_top_chains() {
    [ "$chains_ready" = 1 ] && return 0
    local T _rc
    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        $T -t mangle -N "$CHAIN_UP" 2>/dev/null || $T -t mangle -F "$CHAIN_UP"
        $T -t mangle -N "$CHAIN_DOWN" 2>/dev/null || $T -t mangle -F "$CHAIN_DOWN"
        $T -t mangle -A "$CHAIN_DOWN" ! -o "$IFACE" -j RETURN
        $T -t mangle -C FORWARD -j "$CHAIN_UP" 2>/dev/null
        _rc=$?
        [ "$_rc" -eq 1 ] && $T -t mangle -A FORWARD -j "$CHAIN_UP" 2>/dev/null
        $T -t mangle -C POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
        _rc=$?
        if [ "$_rc" -eq 1 ]; then
            # 必须严格排在 HNC_SAVE 之后(OEM 规则占前排时 -I POSTROUTING 2 会跑到 HNC_SAVE 之前,
            # 导致 0x900000+i 被写入 ctmark 污染设备级限速)!
            _save_ln=$($T -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$2 == "HNC_SAVE" {print $1; exit}')
            if [ -n "$_save_ln" ]; then
                $T -t mangle -I POSTROUTING $((_save_ln + 1)) -j "$CHAIN_DOWN" 2>/dev/null \
                    || $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            else
                $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            fi
        fi
    done
    chains_ready=1
}

next_slot=1
get_or_init_client_subchain() {
    local mac=$1 v4=$2 v6s=$3 slot cs_hex sub v6
    slot=$(awk -v m="$mac" '$1==m{print $2; exit}' "$SLOT_MAP" 2>/dev/null)
    if [ -n "$slot" ]; then
        echo "HNC_AL_C$slot"
        return 0
    fi
    [ "$next_slot" -gt 254 ] && { echo ""; return 1; }
    ensure_top_chains
    slot=$next_slot
    next_slot=$((next_slot + 1))
    echo "$mac $slot" >> "$SLOT_MAP"
    cs_hex=$(printf '0x%02x000000' "$slot")
    sub="HNC_AL_C$slot"

    $IPT -t mangle -N "$sub" 2>/dev/null || $IPT -t mangle -F "$sub"
    $IPT -t mangle -A "$CHAIN_UP" -i "$IFACE" -m mac --mac-source "$mac" \
        -j CONNMARK --set-xmark "$cs_hex/0xff000000" 2>/dev/null
    $IPT -t mangle -A "$CHAIN_DOWN" -m connmark --mark "$cs_hex/0xff000000" -g "$sub" 2>/dev/null
    [ -n "$v4" ] && $IPT -t mangle -A "$CHAIN_DOWN" -d "$v4" -g "$sub" 2>/dev/null

    if [ "$IPV6_OK" = 1 ]; then
        $IP6T -t mangle -N "$sub" 2>/dev/null || $IP6T -t mangle -F "$sub"
        $IP6T -t mangle -A "$CHAIN_UP" -i "$IFACE" -m mac --mac-source "$mac" \
            -j CONNMARK --set-xmark "$cs_hex/0xff000000" 2>/dev/null
        $IP6T -t mangle -A "$CHAIN_DOWN" -m connmark --mark "$cs_hex/0xff000000" -g "$sub" 2>/dev/null
        for v6 in $v6s; do
            $IP6T -t mangle -A "$CHAIN_DOWN" -d "$v6" -g "$sub" 2>/dev/null
        done
    fi
    echo "$sub"
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

# ─── Step 3: Walk limits & emit dual-stack rules ──────────────────────
i=0
applied=0
skipped=0
had_err=0
while IFS=' ' read -r MAC APP RATE _; do
    [ -z "$MAC" ] && continue
    case "$MAC" in '#'*) continue ;; esac
    MAC=$(echo "$MAC" | tr 'A-Z' 'a-z')
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
    APP_IPS=$(echo "$SPLIT" | awk '$1=="K"{print $2}' | sort -u)
    n_total=$(echo "$SPLIT" | grep -cE '^[KS] ')
    n_shared=$(echo "$SPLIT" | grep -c '^S ')
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
    SUB_CHAIN=$(get_or_init_client_subchain "$MAC" "$CLIENT_IP" "$CLIENT_IP6S")
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
                    $IP6T -t mangle -A "$SUB_CHAIN" -s "$IP" -j MARK --set-mark "$MARK" 2>/dev/null && n_v6=$((n_v6 + 1))
                fi
                ;;
            *)
                $IPT -t mangle -A "$SUB_CHAIN" -s "$IP" -j MARK --set-mark "$MARK" 2>/dev/null && n_v4=$((n_v4 + 1))
                ;;
        esac
    done

    n_ips=$((n_v4 + n_v6))
    echo "$MAC $APP $n_total $n_shared $n_ips" >> "$IPSTATS_FLAT.tmp"
    APP_SIG="$APP_SIG$CID=$RATE_MBIT,"
    log "applied $MAC (v4=${CLIENT_IP:-none}) / $APP / ${RATE_KBIT}kbit / ips=${n_ips}(v4=$n_v4,v6=$n_v6,shared_skip=$n_shared) / mark=$MARK class=$CID"
    applied=$((applied + 1))
    i=$((i + 1))
done < "$LIMITS_FLAT"

if [ "$had_err" = 0 ]; then
    {
        printf 'iface=%s|v6=%s\n' "$IFACE" "$IPV6_OK"
        cat "$LIMITS_FLAT" 2>/dev/null
        cat "$IP_APP_FLAT" 2>/dev/null
        cat "$DEVICES" 2>/dev/null
        ip -6 neigh show dev "$IFACE" 2>/dev/null | awk '$1 ~ /:/ && tolower($1) !~ /^(fe80:|ff)/ && $1 != "::1" && $NF != "FAILED" && $NF != "INCOMPLETE" {for(i=2;i<NF;i++) if($i=="lladdr") print tolower($1), tolower($(i+1))}' | sort
    } | cksum | awk '{print $1 "-" $2}' > "$FULL_SIG_FILE" 2>/dev/null
else
    rm -f "$FULL_SIG_FILE" 2>/dev/null
fi

log "summary: applied=$applied skipped=$skipped err=$had_err ipv6=$IPV6_OK"
mv -f "$IPSTATS_FLAT.tmp" "$IPSTATS_FLAT" 2>/dev/null || true
rm -f "${DIRTY}.processing" 2>/dev/null
tc_snapshot_if_changed
