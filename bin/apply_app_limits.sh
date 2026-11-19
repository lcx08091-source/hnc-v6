#!/system/bin/sh
# apply_app_limits.sh — HNC v5.40.0: 双栈按设备单应用限速引擎 (HTB 父子层级归位 + 32位正交位域 + 双栈 QUIC 回落)
#
# 核心重构 (v5.40.0 T2 第 2、7、8 项):
#   1. 父子层级归位: 每条单应用限速类 1:9001..9998 严格挂在对应客户端的设备 HTB 类 parent 1:<cid> 下
#      (若该设备未开整机限速, 自动以全局上限或 1000mbit 创建 1:<cid> 及根 pref 1 handle <dev_mark>/0x00ff0000 fw),
#      且应用类 ceil 严格钳制 <= 父设备 ceil, 彻底杜绝多个应用限速之和冲破设备总带宽上限!
#   2. 正交高位打标: [31:26] 0xfc000000 段 (slot 1..63 -> (slot << 26)/0xfc000000),
#      并在 parent 1:<cid> 挂 protocol all prio 1 handle <app_mark>/0xfc000000 fw flowid 1:<app_cls>。
#   3. 防内核 sch_htb 逃逸至 1:9999: 若某台开启单应用限速的设备未开启 app_qos, 自动在 parent 1:<cid> 下创建
#      默认兜底子类 1:9eXX (0x9e00 + mid, rate=剩余带宽至少 1000kbit, ceil=父设备 ceil, 挂 fq_codel) 及
#      prio 9 u32 match u32 0 0 兜底过滤器; 若已开启 app_qos, 非受限应用流量自然落入 prio 2/9 的 1:a0XX 三档队列!
#   4. 受限应用双栈 QUIC 定向回落 TCP: 在 filter 表维护双栈 HNC_QUIC_APPLIM 链, 对受限应用目标 IPv4/IPv6
#      的 udp --dport 443 返回 REJECT (icmp-port-unreachable / icmp6-port-unreachable)。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN="$HNC_DIR/run"
LIMITS_FLAT="$HNC_DIR/data/app_limits.flat"
IP_APP_FLAT="$HNC_DIR/run/ip_app_map.flat"
DEVICES="$HNC_DIR/data/devices.json"
RULES="$HNC_DIR/data/rules.json"
DIRTY="$HNC_DIR/run/app_limit.dirty"
LOG="$HNC_DIR/logs/app_limits.log"
TCM="$HNC_DIR/bin/tc_manager.sh"

APP_SIG_FILE="$RUN/app_limits.applied.sig"
FULL_SIG_FILE="$RUN/app_limits.full_state.sig"
INACTIVE_MARKER="$RUN/app_limits_inactive.marker"
IPSTATS_FLAT="$RUN/app_limits_ipstats.flat"
AL_DEVS_FILE="$RUN/app_limits.devs"
AL_TREE_FILE="$RUN/app_limits.tree"
AQ_STATE_FILE="$RUN/app_qos.state"

if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi
command -v hnc_dev_mark_hex >/dev/null 2>&1 || {
    hnc_dev_mark_hex() { printf '0x%08x\n' $(( 0x00800000 | ($1 << 16) )); }
}
command -v hnc_applim_mark_hex >/dev/null 2>&1 || {
    hnc_applim_mark_hex() { printf '0x%08x\n' $(( ($1 & 63) << 26 )); }
}

DEV_MASK="${HNC_MARK_MASK:-0x00ff0000}"
APPLIM_MASK="${HNC_APPLIM_MASK:-0xfc000000}"
APP_CLASS_MINOR_BASE=36864  # 0x9000 -> 1:9001..1:9998
APP_CLASS_MINOR_MAX=39320   # 0x9998 (避开默认类 1:9999 = 0x9999)
DEF_CLASS_MINOR_BASE=40448  # 0x9e00 -> 1:9e01..1:9e63 (每设备默认兜底子类)
DEF_CLASS_MINOR_MAX=40550
CHAIN_UP=HNC_APP_LIMIT_UP
CHAIN_DOWN=HNC_APP_LIMIT_DOWN
CHAIN_QUIC=HNC_QUIC_APPLIM
LEGACY_CHAIN=HNC_APP_LIMIT
INNER_PRIO_APP=1
INNER_PRIO_DEF=9

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
        cat "$RULES" 2>/dev/null
        cat "$AQ_STATE_FILE" 2>/dev/null
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
       && $IPT -t filter -C FORWARD -j "$CHAIN_QUIC" 2>/dev/null \
       && { [ "$IPV6_OK" = 0 ] || { $IP6T -t mangle -C FORWARD -j "$CHAIN_UP" 2>/dev/null && $IP6T -t mangle -C POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null && $IP6T -t filter -C FORWARD -j "$CHAIN_QUIC" 2>/dev/null; }; } \
       && tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb 1:" \
       && app_classes_alive; then
        al_unlock
        exit 0
    fi
fi

class_for_mid() { if [ "$1" = "1" ]; then echo 100; else printf '%d' "$1"; fi; }
def_minor_for_mid() { printf '%x' $((0x9e00 + $1)); }
has_app_qos_on_dev() { [ -f "$AQ_STATE_FILE" ] && grep -qx "$1 $2" "$AQ_STATE_FILE" 2>/dev/null; }

to_kbit() {
    awk -v v="$1" 'BEGIN{
        n = v + 0; u = v; sub(/^[0-9.]+/, "", u); u = tolower(u)
        if (u ~ /^g/) k = n * 1000000; else if (u ~ /^m/) k = n * 1000; else if (u ~ /^k/) k = n; else k = n / 1000
        k = int(k + 0.5); if (k < 1) k = 1; print k }'
}

# 解析 rules.json 中设备的已有 mark_id 和 down_mbps
rules_dev_info() {
    local mac=$1
    [ -f "$RULES" ] || return 0
    tr -d '\r\n' < "$RULES" 2>/dev/null | awk -v m="$mac" '
    {
        s = $0; m = tolower(m)
        if (!match(s, /"devices"[[:space:]]*:[[:space:]]*\{/)) exit
        i = RSTART + RLENGTH; n = length(s); depth = 1
        while (i <= n && depth > 0) {
            c = substr(s, i, 1)
            if (c == "\"") {
                j = i + 1
                while (j <= n) {
                    d = substr(s, j, 1)
                    if (d == "\\") { j += 2; continue }
                    if (d == "\"") break
                    j++
                }
                key = substr(s, i + 1, j - i - 1)
                i = j + 1
                if (depth == 1 && tolower(key) == m) {
                    rest = substr(s, i)
                    if (!match(rest, /^[[:space:]]*:[[:space:]]*\{/)) continue
                    k = i + RLENGTH; bd = 1; ins = 0; st = k
                    while (k <= n && bd > 0) {
                        e = substr(s, k, 1)
                        if (ins) { if (e == "\\") k++; else if (e == "\"") ins = 0 }
                        else if (e == "\"") ins = 1
                        else if (e == "{") bd++
                        else if (e == "}") bd--
                        k++
                    }
                    blk = substr(s, st, k - st)
                    mid = ""; dn = "0"; le = "false"
                    if (match(blk, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                        seg = substr(blk, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", seg); mid = seg
                    }
                    if (match(blk, /"down_mbps"[[:space:]]*:[[:space:]]*[0-9.]+/)) {
                        seg = substr(blk, RSTART, RLENGTH); sub(/.*:[[:space:]]*/, "", seg); dn = seg
                    }
                    if (match(blk, /"limit_enabled"[[:space:]]*:[[:space:]]*true/)) {
                        le = "true"
                    }
                    print mid, dn, le
                    exit
                }
                continue
            }
            if (c == "{") depth++
            else if (c == "}") depth--
            i++
        }
    }'
}

alloc_ephemeral_mid() {
    local mac=$1 used_extra="$2" used lb start k cand
    used=$(awk '
    {
        s = $0
        while (match(s, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
            seg = substr(s, RSTART, RLENGTH)
            if (match(seg, /[0-9]+$/)) print substr(seg, RSTART, RLENGTH)
            s = substr(s, RSTART + RLENGTH)
        }
    }' "$RULES" 2>/dev/null)
    used="$used
$used_extra"
    lb=$(printf '%s' "$mac" | awk -F: '{print $6}')
    start=$((0x${lb:-1} % 99 + 1))
    k=0
    while [ "$k" -lt 99 ]; do
        cand=$(((start - 1 + k) % 99 + 1))
        if ! printf '%s\n' "$used" | grep -qx "$cand"; then
            echo "$cand"
            return 0
        fi
        k=$((k + 1))
    done
    return 1
}

cleanup_quic_applim() {
    local T _k
    for T in "$IPT" "$([ "$IPV6_OK" = 1 ] && echo "$IP6T")"; do
        [ -z "$T" ] && continue
        for _k in 1 2 3 4; do $T -t filter -D FORWARD -j "$CHAIN_QUIC" 2>/dev/null || break; done
        $T -t filter -F "$CHAIN_QUIC" 2>/dev/null || true
        $T -t filter -X "$CHAIN_QUIC" 2>/dev/null || true
    done
}

cleanup_ipt_app_limits() {
    local T rbin sub c _k _batch _fam _subs
    cleanup_quic_applim
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
            # v5.40.2: 插入到 HNC_SAVE 之前, 使 [31:24] 单应用标记同步写入 CONNMARK, 防止尾部 HNC_EGRESS_FIX 还原时清零 [31:24]
            _save_ln=$($T -t mangle -L POSTROUTING -n --line-numbers 2>/dev/null | awk '$2 == "HNC_SAVE" {print $1; exit}')
            if [ -n "$_save_ln" ]; then
                $T -t mangle -I POSTROUTING "$_save_ln" -j "$CHAIN_DOWN" 2>/dev/null \
                    || $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            else
                $T -t mangle -A POSTROUTING -j "$CHAIN_DOWN" 2>/dev/null
            fi
        fi
    done
}

replay_al_batch_fallback() {
    local T=$1 batch=$2 tbl=${3:-mangle} line _ch
    [ -s "$batch" ] || return 0
    while IFS= read -r line; do
        case "$line" in
            ''|'# '*'*'|'*mangle'|'*filter'|'COMMIT') continue ;;
            :*' - [0:0]')
                _ch=${line#:}
                _ch=${_ch%% *}
                $T -t "$tbl" -N "$_ch" 2>/dev/null || $T -t "$tbl" -F "$_ch" 2>/dev/null
                ;;
            -A\ *)
                set -f
                # shellcheck disable=SC2086
                set -- $line
                set +f
                $T -t "$tbl" "$@" 2>/dev/null
                ;;
        esac
    done < "$batch"
}

LAST_RESET_DEVS=""
# 拆除旧单应用限速 TC 子类与过滤器 ($1=restore_leaves: 1=给不再拥有子类的父设备补回默认叶子)
reset_tc_app_limits() {
    local restore_leaves="${1:-0}" _p _proto cid par minor_hex minor_dec prev_devs _scan_tmp _pcid _pmid
    prev_devs=""
    [ -f "$AL_TREE_FILE" ] && prev_devs=$(awk '$1=="DEV"{print $2, $3, $4, $5}' "$AL_TREE_FILE" 2>/dev/null)

    # 兼容清理历史遗留根级 prio 2/200/199 过滤器
    for _p in 2 200 199; do
        for _proto in all ip ipv6; do
            tc filter del dev "$IFACE" parent 1: prio "$_p" protocol "$_proto" 2>/dev/null || true
        done
    done

    # 先按 AL_TREE_FILE 拆除各父设备 1:<cid> 下的 prio 1 (以及无 app_qos 时的 prio 9) 过滤器和子类
    if [ -f "$AL_TREE_FILE" ]; then
        awk '$1=="DEV"{print $2, $3}' "$AL_TREE_FILE" 2>/dev/null | while read -r d_if d_cid; do
            [ -n "$d_if" ] && [ -n "$d_cid" ] || continue
            tc filter del dev "$d_if" parent "1:$d_cid" prio "$INNER_PRIO_APP" 2>/dev/null || true
            if ! has_app_qos_on_dev "$d_if" "$d_cid"; then
                tc filter del dev "$d_if" parent "1:$d_cid" prio "$INNER_PRIO_DEF" 2>/dev/null || true
            fi
        done
        awk '$1=="APP" || $1=="DEF"{print $2, $4}' "$AL_TREE_FILE" 2>/dev/null | while read -r d_if sub_cid; do
            [ -n "$d_if" ] && [ -n "$sub_cid" ] || continue
            tc class del dev "$d_if" classid "$sub_cid" 2>/dev/null || true
        done
    fi

    # 扫描内核实际存在的 1:9001..9998 与 1:9e01..9e63 兜底清理:
    # 使用临时文件避免管道子 shell 丢失受影响父设备记录, 当状态文件缺失时也能从 parent 1:<cid> 反推补回默认叶子!
    _scan_tmp="$RUN/.al_kscan.$$"
    tc class show dev "$IFACE" 2>/dev/null | awk '$1=="class" && $2=="htb" {
        par=""; for(i=4;i<=NF;i++) if($i=="parent") par=$(i+1);
        print $3, par
    }' > "$_scan_tmp"
    while read -r cid par; do
        [ -n "$cid" ] || continue
        minor_hex=${cid#*:}
        minor_dec=$(printf '%d' "0x$minor_hex" 2>/dev/null) || continue
        if { [ "$minor_dec" -gt "$APP_CLASS_MINOR_BASE" ] && [ "$minor_dec" -le "$APP_CLASS_MINOR_MAX" ]; } || \
           { [ "$minor_dec" -gt "$DEF_CLASS_MINOR_BASE" ] && [ "$minor_dec" -le "$DEF_CLASS_MINOR_MAX" ]; }; then
            if [ -n "$par" ] && [ "$par" != "1:1" ] && [ "$par" != "root" ]; then
                _pcid=${par#1:}
                tc filter del dev "$IFACE" parent "$par" prio "$INNER_PRIO_APP" 2>/dev/null || true
                if ! has_app_qos_on_dev "$IFACE" "$_pcid"; then
                    tc filter del dev "$IFACE" parent "$par" prio "$INNER_PRIO_DEF" 2>/dev/null || true
                fi
                _pmid=""
                if [ "$_pcid" = "100" ]; then
                    _pmid=1
                else
                    case "$_pcid" in
                        ''|*[!0-9]*) ;;
                        *) [ "$_pcid" -ge 2 ] && [ "$_pcid" -le 99 ] 2>/dev/null && _pmid="$_pcid" ;;
                    esac
                fi
                if [ -n "$_pmid" ] && ! printf '%s\n' "$prev_devs" | grep -qE "^${IFACE} ${_pcid} "; then
                    if [ -z "$prev_devs" ]; then
                        prev_devs="$IFACE $_pcid $_pmid -"
                    else
                        prev_devs="$prev_devs
$IFACE $_pcid $_pmid -"
                    fi
                fi
            fi
            tc class del dev "$IFACE" classid "$cid" 2>/dev/null || true
        fi
    done < "$_scan_tmp"
    rm -f "$_scan_tmp" 2>/dev/null

    LAST_RESET_DEVS="$prev_devs"
    rm -f "$AL_DEVS_FILE" "$AL_TREE_FILE" 2>/dev/null

    if [ "$restore_leaves" = "1" ] && [ -n "$prev_devs" ]; then
        printf '%s\n' "$prev_devs" | while read -r d_if d_cid d_mid d_ip; do
            [ -n "$d_if" ] && [ -n "$d_cid" ] && [ -n "$d_mid" ] || continue
            if ! has_app_qos_on_dev "$d_if" "$d_cid"; then
                [ "$d_ip" = "-" ] && d_ip=""
                sh "$TCM" ensure_class "$d_if" "$d_mid" "$d_ip" >/dev/null 2>&1 || true
            fi
        done
    fi
}

if [ ! -s "$LIMITS_FLAT" ]; then
    cleanup_ipt_app_limits
    reset_tc_app_limits 1
    rm -f "$INACTIVE_MARKER" "$FULL_SIG_FILE" "$IPSTATS_FLAT" "${DIRTY}.processing" 2>/dev/null
    log "no app_limits configured (cleaned old dual-stack rules and restored device leaves)"
    tc_snapshot_if_changed
    al_unlock
    exit 0
fi

if [ ! -s "$IP_APP_FLAT" ]; then
    cleanup_ipt_app_limits
    reset_tc_app_limits 1
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

reset_tc_app_limits 0
PREV_DEVS_SNAPSHOT="$LAST_RESET_DEVS"

if [ -z "$HNC_TEST_MODE" ] && ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "htb 1:"; then
    [ -x "$TCM" ] && HNC_SKIP_TC_SNAPSHOT=1 sh "$TCM" init "$IFACE" >/dev/null 2>&1 || true
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

classid_for_index() {
    local minor=$((APP_CLASS_MINOR_BASE + 1 + $1))
    [ "$minor" -gt "$APP_CLASS_MINOR_MAX" ] && { echo ""; return; }
    printf '1:%x\n' "$minor"
}

# 获取全局下行上限 kbit (默认 1000000kbit = 1000mbit)
global_ceil_kbit() {
    local gs_en gs_dn k
    if [ -f "$RULES" ]; then
        gs_en=$(tr -d '\r\n' < "$RULES" 2>/dev/null | sed -nE 's/.*"global_shaper_enabled"[[:space:]]*:[[:space:]]*(true|false).*/\1/p' | head -1)
        if [ "$gs_en" = "true" ]; then
            gs_dn=$(tr -d '\r\n' < "$RULES" 2>/dev/null | sed -nE 's/.*"global_shaper_down"[[:space:]]*:[[:space:]]*"?([0-9.a-zA-Z]+)"?.*/\1/p' | head -1)
            if [ -n "$gs_dn" ] && [ "$gs_dn" != "0" ]; then
                case "$gs_dn" in
                    *[a-zA-Z]*) k=$(to_kbit "$gs_dn") ;;
                    *) k=$(awk -v v="$gs_dn" 'BEGIN{x=int(v*1000+0.5); if(x<1000)x=1000000; print x}') ;;
                esac
                echo "$k"
                return 0
            fi
        fi
    fi
    echo 1000000
}

. "$HNC_DIR/bin/tc_rate_calc.sh" 2>/dev/null || . "$(dirname "$0")/tc_rate_calc.sh"
IPNAME_JSON="$RUN/dpi_ipname.json"
IPNAME_APP_FLAT="$RUN/.ipname_app.flat.$$"
DEV_META_MAP="$RUN/.al_devmeta.$$"
V4_HDR="$RUN/.al_v4_hdr.$$"
V4_RULES="$RUN/.al_v4_rules.$$"
V4_BATCH="$RUN/.al_v4_batch.$$"
V6_HDR="$RUN/.al_v6_hdr.$$"
V6_RULES="$RUN/.al_v6_rules.$$"
V6_BATCH="$RUN/.al_v6_batch.$$"
QUIC_V4_RULES="$RUN/.al_qv4.$$"
QUIC_V6_RULES="$RUN/.al_qv6.$$"
TREE_TMP="$RUN/.al_tree.$$"
DEVS_TMP="$RUN/.al_devs.$$"

INCLUDE_SHARED=0
tr -d '\n' < "$RULES" 2>/dev/null | \
    grep -Eq '"app_limit_include_shared_ips"[[:space:]]*:[[:space:]]*(true|"true"|1|"1"|"on")' && INCLUDE_SHARED=1

{
    echo "#sentinel -"
    tr -d '\n' < "$IPNAME_JSON" 2>/dev/null | \
        grep -oE '"[0-9A-Fa-f.:]+":\{[^{}]*\}' | \
        sed -n 's/^"\([^"]*\)":{.*"app":"\([^"]*\)".*/\1 \2/p'
} > "$IPNAME_APP_FLAT" 2>/dev/null

: > "$IPSTATS_FLAT.tmp" 2>/dev/null
: > "$DEV_META_MAP" 2>/dev/null
: > "$V4_HDR"; : > "$V4_RULES"
: > "$V6_HDR"; : > "$V6_RULES"
: > "$QUIC_V4_RULES"; : > "$QUIC_V6_RULES"
: > "$TREE_TMP"; : > "$DEVS_TMP"
trap 'rm -f "$IPNAME_APP_FLAT" "$IPSTATS_FLAT.tmp" "$DEV_META_MAP" "$V4_HDR" "$V4_RULES" "$V4_BATCH" "$V6_HDR" "$V6_RULES" "$V6_BATCH" "$QUIC_V4_RULES" "$QUIC_V6_RULES" "$TREE_TMP" "$DEVS_TMP" "${DIRTY}.processing" 2>/dev/null; al_unlock' EXIT INT TERM

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

# 确保客户端父设备 HTB 类 1:<dev_cid>、根 fw 过滤器、正交设备打标链 HNC_AL_C<slot> 就绪
# DEV_META_MAP 每行: mac slot mid dev_cid parent_ceil_kbit sum_app_kbit v4
next_client_idx=1
ALLOC_MIDS=""
SUB_CHAIN=""
CUR_DEV_MID=""
CUR_DEV_CID=""
CUR_DEV_CEIL_KBIT=1000000

ensure_parent_device_ready() {
    local mac=$1 v4=$2 v6s=$3 row info mid dn le dev_cid dmark ceil_kbit shown rc_line r_tok c_tok sub v6 b q
    SUB_CHAIN=""
    row=$(awk -v m="$mac" '$1==m{print; exit}' "$DEV_META_MAP" 2>/dev/null)
    if [ -n "$row" ]; then
        set -- $row
        SUB_CHAIN="HNC_AL_C$2"
        CUR_DEV_MID="$3"
        CUR_DEV_CID="$4"
        CUR_DEV_CEIL_KBIT="$5"
        return 0
    fi
    [ "$next_client_idx" -gt 99 ] && return 1

    info=$(rules_dev_info "$mac")
    mid=""; dn="0"; le="false"
    if [ -n "$info" ]; then
        set -- $info
        mid="${1:-}"; dn="${2:-0}"; le="${3:-false}"
    fi
    case "$mid" in ''|*[!0-9]*) mid="" ;; esac
    if [ -z "$mid" ] || [ "$mid" -lt 1 ] || [ "$mid" -gt 99 ]; then
        mid=$(alloc_ephemeral_mid "$mac" "$ALLOC_MIDS") || return 1
        ALLOC_MIDS="$ALLOC_MIDS
$mid"
    fi
    dev_cid=$(class_for_mid "$mid")
    dmark=$(hnc_dev_mark_hex "$mid") || return 1

    # 读取内核现有 1:<dev_cid> ceil, 若不存在则按 rules.json down_mbps 或全局上限自动创建!
    shown=$(tc class show dev "$IFACE" classid "1:$dev_cid" 2>/dev/null)
    if [ -z "$shown" ]; then
        shown=$(tc class show dev "$IFACE" 2>/dev/null)
    fi
    rc_line=$(printf '%s\n' "$shown" | awk -v c0="1:$dev_cid" '
        $1=="class" && $2=="htb" && $3==c0 {
            r=""; c=""
            for(i=4;i<=NF;i++){ if($i=="rate") r=$(i+1); if($i=="ceil") c=$(i+1) }
            if(r!=""){ if(c=="") c=r; print r, c; exit }
        }')

    if [ -n "$rc_line" ]; then
        c_tok=${rc_line#* }
        ceil_kbit=$(to_kbit "$c_tok")
    else
        if [ "$le" = "true" ] && awk -v v="$dn" 'BEGIN{exit !(v+0 > 0)}'; then
            ceil_kbit=$(awk -v v="$dn" 'BEGIN{k=int(v*1000+0.5); if(k<1)k=1; print k}')
        else
            ceil_kbit=$(global_ceil_kbit)
        fi
        local ceil_mbps
        ceil_mbps=$(awk -v k="$ceil_kbit" 'BEGIN{printf "%.2f", k/1000.0}')
        b=$(hnc_burst_k "$ceil_mbps" compat)
        q=$(hnc_quantum "$ceil_mbps")
        if [ -n "$q" ]; then
            tc class add dev "$IFACE" parent 1:1 classid "1:$dev_cid" htb rate "${ceil_kbit}kbit" ceil "${ceil_kbit}kbit" burst "$b" cburst "$b" quantum "$q" 2>/dev/null \
                || tc class add dev "$IFACE" parent 1:1 classid "1:$dev_cid" htb rate "${ceil_kbit}kbit" ceil "${ceil_kbit}kbit" burst "$b" cburst "$b" 2>/dev/null || return 1
        else
            tc class add dev "$IFACE" parent 1:1 classid "1:$dev_cid" htb rate "${ceil_kbit}kbit" ceil "${ceil_kbit}kbit" burst "$b" cburst "$b" 2>/dev/null || return 1
        fi
    fi

    # 确保根 parent 1: 上挂载了正交设备 fw 过滤器 (pref 1 handle <dmark>/0x00ff0000 fw flowid 1:<dev_cid>) 及 IPv4 u32 dst
    tc filter del dev "$IFACE" parent 1: protocol all pref 1 handle "${dmark}/${DEV_MASK}" fw 2>/dev/null || true
    if ! tc filter add dev "$IFACE" parent 1: protocol all pref 1 handle "${dmark}/${DEV_MASK}" fw flowid "1:$dev_cid" 2>/dev/null; then
        tc filter del dev "$IFACE" parent 1: protocol ip pref 1 handle "${dmark}/${DEV_MASK}" fw 2>/dev/null || true
        tc filter add dev "$IFACE" parent 1: protocol ip pref 1 handle "${dmark}/${DEV_MASK}" fw flowid "1:$dev_cid" 2>/dev/null || true
        if [ "$IPV6_OK" = 1 ]; then
            tc filter del dev "$IFACE" parent 1: protocol ipv6 pref 3 handle "${dmark}/${DEV_MASK}" fw 2>/dev/null || true
            tc filter add dev "$IFACE" parent 1: protocol ipv6 pref 3 handle "${dmark}/${DEV_MASK}" fw flowid "1:$dev_cid" 2>/dev/null || true
        fi
    fi
    if [ -n "$v4" ]; then
        local uprio=$((100 + mid))
        tc filter del dev "$IFACE" parent 1: prio "$uprio" 2>/dev/null || true
        tc filter add dev "$IFACE" parent 1: protocol ip prio "$uprio" u32 match ip dst "$v4/32" flowid "1:$dev_cid" 2>/dev/null || true
    fi

    # 若该设备未开 app_qos, 转为内部节点前必须先摘除 1:<dev_cid> 上的直接叶子 qdisc(内核不允许内部节点保留直接挂接的叶子后再行为异常)
    if ! has_app_qos_on_dev "$IFACE" "$dev_cid"; then
        tc qdisc del dev "$IFACE" parent "1:$dev_cid" 2>/dev/null || true
    fi
    tc filter del dev "$IFACE" parent "1:$dev_cid" prio "$INNER_PRIO_APP" 2>/dev/null || true

    init_batch_top
    local cslot=$next_client_idx
    next_client_idx=$((next_client_idx + 1))
    sub="HNC_AL_C$cslot"

    # 使用 [23:16] 0x00ff0000 正交设备段锚定连接与方向(与 HNC_SAVE/HNC_RESTORE 0xffff0000 天然统一, 绝不侵占 [31:26] 应用槽位段!)
    echo ":$sub - [0:0]" >> "$V4_HDR"
    {
        echo "-A $CHAIN_UP -i $IFACE -m mac --mac-source $mac -m mark --mark 0x0/$DEV_MASK -j MARK --set-xmark ${dmark}/${DEV_MASK}"
        echo "-A $CHAIN_DOWN -m mark --mark ${dmark}/${DEV_MASK} -g $sub"
        [ -n "$v4" ] && echo "-A $CHAIN_DOWN -d $v4 -g $sub"
    } >> "$V4_RULES"

    if [ "$IPV6_OK" = 1 ]; then
        echo ":$sub - [0:0]" >> "$V6_HDR"
        {
            echo "-A $CHAIN_UP -i $IFACE -m mac --mac-source $mac -m mark --mark 0x0/$DEV_MASK -j MARK --set-xmark ${dmark}/${DEV_MASK}"
            echo "-A $CHAIN_DOWN -m mark --mark ${dmark}/${DEV_MASK} -g $sub"
            for v6 in $v6s; do
                echo "-A $CHAIN_DOWN -d $v6 -g $sub"
            done
        } >> "$V6_RULES"
    fi

    echo "$mac $cslot $mid $dev_cid $ceil_kbit 0 ${v4:--}" >> "$DEV_META_MAP"
    echo "$IFACE $dev_cid" >> "$DEVS_TMP"
    echo "DEV $IFACE $dev_cid $mid ${v4:--}" >> "$TREE_TMP"

    SUB_CHAIN="$sub"
    CUR_DEV_MID="$mid"
    CUR_DEV_CID="$dev_cid"
    CUR_DEV_CEIL_KBIT="$ceil_kbit"
    return 0
}

add_dev_app_sum() {
    local mac=$1 add_k=$2
    awk -v m="$mac" -v a="$add_k" '
        $1 == m { $6 = $6 + a }
        { print }
    ' "$DEV_META_MAP" > "${DEV_META_MAP}.new" && mv -f "${DEV_META_MAP}.new" "$DEV_META_MAP"
}

add_inner_app_fw() {
    local dev_cid=$1 app_mark=$2 app_cls=$3
    if tc filter add dev "$IFACE" parent "1:$dev_cid" protocol all prio "$INNER_PRIO_APP" \
            handle "${app_mark}/${APPLIM_MASK}" fw flowid "$app_cls" 2>/dev/null; then
        return 0
    fi
    tc filter add dev "$IFACE" parent "1:$dev_cid" protocol ip prio "$INNER_PRIO_APP" \
        handle "${app_mark}/${APPLIM_MASK}" fw flowid "$app_cls" 2>/dev/null || return 1
    if [ "$IPV6_OK" = 1 ]; then
        tc filter add dev "$IFACE" parent "1:$dev_cid" protocol ipv6 prio "$INNER_PRIO_APP" \
            handle "${app_mark}/${APPLIM_MASK}" fw flowid "$app_cls" 2>/dev/null || return 1
    fi
    return 0
}

rollback_app_tc() {
    local dev_cid=$1 app_mark=$2 app_cls=$3
    tc filter del dev "$IFACE" parent "1:$dev_cid" protocol all prio "$INNER_PRIO_APP" handle "${app_mark}/${APPLIM_MASK}" fw 2>/dev/null || true
    tc filter del dev "$IFACE" parent "1:$dev_cid" protocol ip prio "$INNER_PRIO_APP" handle "${app_mark}/${APPLIM_MASK}" fw 2>/dev/null || true
    tc filter del dev "$IFACE" parent "1:$dev_cid" protocol ipv6 prio "$INNER_PRIO_APP" handle "${app_mark}/${APPLIM_MASK}" fw 2>/dev/null || true
    tc class del dev "$IFACE" classid "$app_cls" 2>/dev/null || true
}

i=0
app_slot=0
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

    next_slot_cand=$((app_slot + 1))
    if [ "$next_slot_cand" -gt 63 ]; then
        log "skip $MAC/$APP: orthogonal [31:26] app_limits slot exhausted (>63)"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi
    CID=$(classid_for_index "$i")
    if [ -z "$CID" ]; then
        log "skip $MAC/$APP: classid space exhausted"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi
    if ! ensure_parent_device_ready "$MAC" "$CLIENT_IP" "$CLIENT_IP6S" || [ -z "$SUB_CHAIN" ]; then
        log "skip $MAC/$APP: parent device class setup failed"
        had_err=1
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    app_slot=$next_slot_cand
    MARK=$(hnc_applim_mark_hex "$app_slot")

    RATE_KBIT=$(awk -v v="$RATE" 'BEGIN{k=int(v*1000+0.5); if(k<1)k=1; print k}')
    # 铁律: 应用类 ceil 绝不允许超过父设备总 ceil!
    EFF_CEIL_KBIT=$RATE_KBIT
    if [ "$EFF_CEIL_KBIT" -gt "$CUR_DEV_CEIL_KBIT" ]; then
        EFF_CEIL_KBIT=$CUR_DEV_CEIL_KBIT
    fi
    EFF_RATE_KBIT=$EFF_CEIL_KBIT
    EFF_MBPS=$(awk -v k="$EFF_RATE_KBIT" 'BEGIN{printf "%.2f", k/1000.0}')
    RATE_MBIT=$(printf '%.2f' "$RATE")
    APP_BURST=$(hnc_burst_k "$EFF_MBPS" compat)
    APP_QUANTUM=$(hnc_quantum "$EFF_MBPS")
    APP_LEAF_HEX=${CID#1:}

    _cls_ok=0
    if [ -n "$APP_QUANTUM" ] && tc class add dev "$IFACE" parent "1:$CUR_DEV_CID" classid "$CID" htb \
        rate "${EFF_RATE_KBIT}kbit" ceil "${EFF_CEIL_KBIT}kbit" prio 0 \
        burst "$APP_BURST" cburst "$APP_BURST" quantum "$APP_QUANTUM" 2>/dev/null; then
        _cls_ok=1
    elif tc class add dev "$IFACE" parent "1:$CUR_DEV_CID" classid "$CID" htb \
        rate "${EFF_RATE_KBIT}kbit" ceil "${EFF_CEIL_KBIT}kbit" prio 0 \
        burst "$APP_BURST" cburst "$APP_BURST" 2>/dev/null; then
        _cls_ok=1
    fi
    if [ "$_cls_ok" = 1 ]; then
        tc qdisc replace dev "$IFACE" parent "$CID" handle "${APP_LEAF_HEX}:" fq_codel 2>/dev/null \
            || tc qdisc replace dev "$IFACE" parent "$CID" handle "${APP_LEAF_HEX}:" pfifo 2>/dev/null || true
    fi
    if [ "$_cls_ok" != 1 ] || ! add_inner_app_fw "$CUR_DEV_CID" "$MARK" "$CID"; then
        log "ERROR: tc class/filter setup failed for $MAC/$APP (parent=1:$CUR_DEV_CID cid=$CID mark=$MARK), rolling back rule"
        rollback_app_tc "$CUR_DEV_CID" "$MARK" "$CID"
        had_err=1
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    add_dev_app_sum "$MAC" "$EFF_RATE_KBIT"
    echo "APP $IFACE 1:$CUR_DEV_CID $CID" >> "$TREE_TMP"

    n_v4=0
    n_v6=0
    for IP in $APP_IPS; do
        case "$IP" in
            *[!0-9a-fA-F:./]*|'') continue ;;
            *:*)
                if [ "$IPV6_OK" = 1 ]; then
                    echo "-A $SUB_CHAIN -s $IP -j MARK --set-xmark ${MARK}/${APPLIM_MASK}" >> "$V6_RULES"
                    echo "-A $CHAIN_QUIC -i $IFACE -m mac --mac-source $MAC -d $IP -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable" >> "$QUIC_V6_RULES"
                    n_v6=$((n_v6 + 1))
                fi
                ;;
            *)
                echo "-A $SUB_CHAIN -s $IP -j MARK --set-xmark ${MARK}/${APPLIM_MASK}" >> "$V4_RULES"
                echo "-A $CHAIN_QUIC -i $IFACE -m mac --mac-source $MAC -d $IP -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable" >> "$QUIC_V4_RULES"
                n_v4=$((n_v4 + 1))
                ;;
        esac
    done

    n_ips=$((n_v4 + n_v6))
    echo "$MAC $APP $n_total $n_shared $n_ips" >> "$IPSTATS_FLAT.tmp"
    APP_SIG="$APP_SIG$CID=$RATE_MBIT,"
    log "applied $MAC (v4=${CLIENT_IP:-none}, parent=1:$CUR_DEV_CID) / $APP / ${EFF_RATE_KBIT}kbit(ceil=${EFF_CEIL_KBIT}kbit) / ips=${n_ips}(v4=$n_v4,v6=$n_v6,shared_skip=$n_shared) / mark=${MARK}/${APPLIM_MASK} class=$CID"
    applied=$((applied + 1))
    i=$((i + 1))
done < "$LIMITS_FLAT"

# 为每台开启了单应用限速但【未开启 app_qos】的设备建立默认兜底子类 1:9eXX + prio 9 u32 兜底过滤器!
if [ "$applied" -gt 0 ] && [ -s "$DEV_META_MAP" ]; then
    while read -r d_mac d_slot d_mid d_cid d_ceil d_sum d_ip; do
        [ -n "$d_cid" ] || continue
        if has_app_qos_on_dev "$IFACE" "$d_cid"; then
            log "device $d_mac (1:$d_cid) has active app_qos; non-limited apps fall through to prio 2/9 1:a0XX tiers"
            continue
        fi
        def_hex=$(def_minor_for_mid "$d_mid")
        rem_kbit=$((d_ceil - d_sum))
        [ "$rem_kbit" -lt 1000 ] && rem_kbit=1000
        [ "$rem_kbit" -gt "$d_ceil" ] && rem_kbit=$d_ceil
        tc class change dev "$IFACE" parent "1:$d_cid" classid "1:$def_hex" htb rate "${rem_kbit}kbit" ceil "${d_ceil}kbit" prio 2 2>/dev/null \
            || tc class add dev "$IFACE" parent "1:$d_cid" classid "1:$def_hex" htb rate "${rem_kbit}kbit" ceil "${d_ceil}kbit" prio 2 2>/dev/null || true
        tc qdisc replace dev "$IFACE" parent "1:$def_hex" handle "${def_hex}:" fq_codel 2>/dev/null \
            || tc qdisc replace dev "$IFACE" parent "1:$def_hex" handle "${def_hex}:" pfifo 2>/dev/null || true
        tc filter del dev "$IFACE" parent "1:$d_cid" prio "$INNER_PRIO_DEF" 2>/dev/null || true
        if ! tc filter add dev "$IFACE" parent "1:$d_cid" protocol all prio "$INNER_PRIO_DEF" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null; then
            tc filter add dev "$IFACE" parent "1:$d_cid" protocol ip prio "$INNER_PRIO_DEF" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null || true
            [ "$IPV6_OK" = 1 ] && tc filter add dev "$IFACE" parent "1:$d_cid" protocol ipv6 prio "$INNER_PRIO_DEF" u32 match u32 0 0 flowid "1:$def_hex" 2>/dev/null || true
        fi
        echo "DEF $IFACE 1:$d_cid 1:$def_hex" >> "$TREE_TMP"
    done < "$DEV_META_MAP"
fi

# 如果上次有设备在 app_limits.devs 中、而本轮不再有任何激活的单应用限速规则, 为其补回默认叶子!
if [ -n "$PREV_DEVS_SNAPSHOT" ]; then
    printf '%s\n' "$PREV_DEVS_SNAPSHOT" | while read -r p_if p_cid p_mid p_ip; do
        [ -n "$p_if" ] && [ -n "$p_cid" ] || continue
        if ! grep -qx "$p_if $p_cid" "$DEVS_TMP" 2>/dev/null && ! has_app_qos_on_dev "$p_if" "$p_cid"; then
            [ "$p_ip" = "-" ] && p_ip=""
            sh "$TCM" ensure_class "$p_if" "$p_mid" "$p_ip" >/dev/null 2>&1 || true
        fi
    done
fi

if [ "$applied" -gt 0 ] && [ "$batch_top_inited" = 1 ]; then
    sort -u "$DEVS_TMP" > "$AL_DEVS_FILE" 2>/dev/null
    mv -f "$TREE_TMP" "$AL_TREE_FILE" 2>/dev/null
    used_slots=$((next_client_idx - 1))
    {
        echo "*mangle"
        cat "$V4_HDR"
        cat "$V4_RULES"
        echo "COMMIT"
    } > "$V4_BATCH"
    if ! run_restore_noflush "$IPT_RESTORE_BIN" "$V4_BATCH"; then
        replay_al_batch_fallback "$IPT" "$V4_BATCH" mangle
    fi

    if [ "$IPV6_OK" = 1 ]; then
        {
            echo "*mangle"
            cat "$V6_HDR"
            cat "$V6_RULES"
            echo "COMMIT"
        } > "$V6_BATCH"
        if ! run_restore_noflush "$IP6T_RESTORE_BIN" "$V6_BATCH"; then
            replay_al_batch_fallback "$IP6T" "$V6_BATCH" mangle
        fi
    fi

    # 同步双栈 filter/HNC_QUIC_APPLIM: 定向拒绝受限应用 UDP 443 迫使秒级回退 TCP
    $IPT -t filter -N "$CHAIN_QUIC" 2>/dev/null || $IPT -t filter -F "$CHAIN_QUIC" 2>/dev/null
    if [ -s "$QUIC_V4_RULES" ]; then
        sort -u "$QUIC_V4_RULES" > "${QUIC_V4_RULES}.u"
        replay_al_batch_fallback "$IPT" "${QUIC_V4_RULES}.u" filter
        rm -f "${QUIC_V4_RULES}.u" 2>/dev/null
    fi
    if ! $IPT -t filter -C FORWARD -j "$CHAIN_QUIC" 2>/dev/null; then
        $IPT -t filter -I FORWARD 1 -j "$CHAIN_QUIC" 2>/dev/null || $IPT -t filter -A FORWARD -j "$CHAIN_QUIC" 2>/dev/null || true
    fi

    if [ "$IPV6_OK" = 1 ]; then
        $IP6T -t filter -N "$CHAIN_QUIC" 2>/dev/null || $IP6T -t filter -F "$CHAIN_QUIC" 2>/dev/null
        if [ -s "$QUIC_V6_RULES" ]; then
            sort -u "$QUIC_V6_RULES" > "${QUIC_V6_RULES}.u"
            replay_al_batch_fallback "$IP6T" "${QUIC_V6_RULES}.u" filter
            rm -f "${QUIC_V6_RULES}.u" 2>/dev/null
        fi
        if ! $IP6T -t filter -C FORWARD -j "$CHAIN_QUIC" 2>/dev/null; then
            $IP6T -t filter -I FORWARD 1 -j "$CHAIN_QUIC" 2>/dev/null || $IP6T -t filter -A FORWARD -j "$CHAIN_QUIC" 2>/dev/null || true
        fi
    fi

    ensure_top_hooks
    prune_stale_subchains "$used_slots"

    if [ -z "${HNC_TEST_MODE:-}" ] && [ -x "$HNC_DIR/bin/hnc_ipc" ]; then
        "$HNC_DIR/bin/hnc_ipc" OFFLOAD_DISABLE_GLOBAL >/dev/null 2>&1 || true
    fi
else
    cleanup_ipt_app_limits
    rm -f "$AL_DEVS_FILE" "$AL_TREE_FILE" 2>/dev/null
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
