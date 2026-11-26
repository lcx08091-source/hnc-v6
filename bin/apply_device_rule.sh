#!/system/bin/sh
# apply_device_rule.sh — Patch 3.b.1 · Go /api/action 调用的应用脚本
#
# 设计目标:封装 WebUI applyLimit 的完整链路 (mark + tc set_limit + json 写入)
# 让 Go httpd 一次 exec 完成"远端设限速→实际生效"
#
# 用法:
#   apply_device_rule.sh limit  <mac> <down_mbps> <up_mbps>
#   apply_device_rule.sh clear  <mac>
#   apply_device_rule.sh bl_add <mac>
#   apply_device_rule.sh bl_del <mac>
#
# 输出: stdout 行 "ok\n" 或 "error: <reason>\n",exit 0/1
#
# 关键差异 vs WebUI 的 applyLimit:
#   - mid 查 rules.json 复用,不存在则按 MAC 哈希分配 + 线性探测避碰
#   - IP 从 devices.json 现读 (不信任 caller 传入)

HNC_DIR=${HNC_DIR:-/data/local/hnc}

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

is_authoritative_wlan0_ap() {
    local _jf="$HNC_DIR/run/iface_detect.json"
    [ -f "$_jf" ] || return 1
    grep -q '"authoritative"[[:space:]]*:[[:space:]]*true' "$_jf" 2>/dev/null \
        && grep -q '"wlan0_ap"[[:space:]]*:[[:space:]]*true' "$_jf" 2>/dev/null
}

RULES="$HNC_DIR/data/rules.json"
DEVICES="$HNC_DIR/data/devices.json"
JSON_SET="$HNC_DIR/bin/json_set.sh"
IPT="$HNC_DIR/bin/iptables_manager.sh"
TC="$HNC_DIR/bin/tc_manager.sh"
DETECT="$HNC_DIR/bin/device_detect.sh"
LOG="$HNC_DIR/logs/apply.log"
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
elif [ -f "${0%/*}/hnc_constants.sh" ]; then
    . "${0%/*}/hnc_constants.sh"
fi

# v5.0: scheduler notify helper
# tc 规则发生变化后调, 让 scheduler 决定是否触发 BPF disable_upstream
HNC_IPC="$HNC_DIR/bin/hnc_ipc"
notify_offload() {
    local mac="$1"
    local flag="$2"   # 1=limited / 0=cleared
    [ -x "$HNC_IPC" ] || return 0   # 二进制不在 (老版本 hotspotd 或 build 没装) → silently skip
    "$HNC_IPC" OFFLOAD_NOTIFY_LIMIT "$mac" "$flag" >> "$LOG" 2>&1 || \
        log "notify_offload mac=$mac flag=$flag failed (non-fatal)"
}

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(date '+%H:%M:%S')] [APPLY] $*" >> "$LOG" 2>/dev/null || true
}

emit_err() {
    log "ERROR: $1"
    echo "error: $1"
    exit 1
}

# v5.1.0-rc1 hotfix: busybox ash 安全数值判断,支持整数/小数。
# 用于 clear 判断 delay/jitter/loss 是否仍然启用。
num_gt0() {
    awk -v v="${1:-0}" 'BEGIN{exit !(v+0 > 0)}'
}

now_ts() {
    date +%s 2>/dev/null || echo 0
}

# ── helper: 读 devices.json 拿 IP ─────────────────────────────────
get_ip() {
    local mac=$1
    [ -f "$DEVICES" ] || { echo ""; return; }
    local _ip
    _ip=$(tr -d '\r\n' < "$DEVICES" 2>/dev/null | awk -v m="$mac" '
    BEGIN { found=0 }
    {
        s = tolower($0)
        needle = "\"" tolower(m) "\""
        pos = 1
        while ((off = index(substr(s, pos), needle)) > 0) {
            idx = pos + off - 1
            tail = substr(s, idx + length(needle))
            if (match(tail, /^[[:space:]]*:[[:space:]]*\{/)) {
                rest = substr(tail, RSTART + RLENGTH)
                depth = 1; ins = 0; endpos = 0; n = length(rest)
                for (i = 1; i <= n && depth > 0; i++) {
                    c = substr(rest, i, 1)
                    if (ins) {
                        if (c == "\\") { i++; continue }
                        if (c == "\"") ins = 0
                    } else {
                        if (c == "\"") ins = 1
                        else if (c == "{") depth++
                        else if (c == "}") { depth--; if (depth == 0) { endpos = i - 1; break } }
                    }
                }
                blk = (endpos > 0) ? substr(rest, 1, endpos) : ""
                if (match(blk, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                    seg = substr(blk, RSTART, RLENGTH)
                    if (match(seg, /[0-9.]+/)) {
                        print substr(seg, RSTART, RLENGTH)
                        found = 1
                        exit
                    }
                }
                exit
            }
            pos = idx + length(needle)
        }
    }
    END { if (!found) print "" }
    ')
    # v5.8.8 (audit): 只回合法 IPv4,挡掉 1.2.3.4.5 这类畸形(awk 已限 [0-9.]、不可注入,
    # 这里再保证四段合法八位组),否则返回空,调用方按"无 IP"处理。
    if valid_ipv4 "$_ip"; then printf '%s\n' "$_ip"; else echo ""; fi
}

# rules.json fallback IP, used when the device is offline but old IP-specific
# iptables DROP/MARK rules need cleanup.
get_rule_ip() {
    local mac=$1 _rip
    _rip=$(sh "$JSON_SET" device_get "$mac" ip 2>/dev/null | awk 'NR==1{print; exit}')
    if [ -z "$_rip" ]; then
        local _lmac
        _lmac=$(printf '%s' "$mac" | tr 'A-Z' 'a-z')
        [ "$_lmac" != "$mac" ] && _rip=$(sh "$JSON_SET" device_get "$_lmac" ip 2>/dev/null | awk 'NR==1{print; exit}')
    fi
    if valid_ipv4 "$_rip"; then printf '%s\n' "$_rip"; else echo ""; fi
}

get_blocked_ip() {
    local mac=$1 _bip
    _bip=$(sh "$JSON_SET" device_get "$mac" blocked_ip 2>/dev/null | awk 'NR==1{print; exit}')
    if [ -z "$_bip" ]; then
        local _lmac
        _lmac=$(printf '%s' "$mac" | tr 'A-Z' 'a-z')
        [ "$_lmac" != "$mac" ] && _bip=$(sh "$JSON_SET" device_get "$_lmac" blocked_ip 2>/dev/null | awk 'NR==1{print; exit}')
    fi
    if valid_ipv4 "$_bip"; then printf '%s\n' "$_bip"; else echo ""; fi
}

# ── helper: 读/分配 mark_id ──────────────────────────────────────
# 1. 优先复用 rules.json 里 devices.<mac>.mark_id
# 2. 没有就按 MAC 后两字节哈希算起点, 在 1-99 范围线性探测避开已用
# v5.12: 只在 devices.<mac> 自己的 {...} 块里取 mark_id。
rules_device_mid() {
    local mac=$1
    [ -f "$RULES" ] || return 0
    tr -d '\n\r' < "$RULES" 2>/dev/null | awk -v m="$mac" '
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
                    if (match(blk, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                        seg = substr(blk, RSTART, RLENGTH)
                        sub(/.*:[[:space:]]*/, "", seg)
                        print seg
                    }
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

get_or_assign_mid() {
    local mac=$1
    local existing
    existing=$(rules_device_mid "$mac")
    if [ -n "$existing" ] && [ "$existing" -ge 1 ] && [ "$existing" -le 99 ] 2>/dev/null; then
        echo "$existing"
        return
    fi
    # 没有: 收集所有 used mark_id
    local used
    used=$(awk '
    {
        s = $0
        while (match(s, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
            seg = substr(s, RSTART, RLENGTH)
            if (match(seg, /[0-9]+$/)) {
                print substr(seg, RSTART, RLENGTH)
            }
            s = substr(s, RSTART + RLENGTH)
        }
    }
    ' "$RULES" 2>/dev/null | sort -u)
    local lb=$(echo "$mac" | awk -F: '{print $6}')
    local start=$((0x${lb:-1} % 99 + 1))
    local k=0
    while [ $k -lt 99 ]; do
        local cand=$(((start - 1 + k) % 99 + 1))
        if ! echo "$used" | grep -qx "$cand"; then
            echo "$cand"
            return 0
        fi
        k=$((k + 1))
    done
    log "ERROR: mark_id exhausted for mac=$mac (all 1..99 are used)"
    return 1
}

JSON_FAILED=""
JSET_BUF=""
BATCH_HELPER="$HNC_DIR/bin/json_set_batch.sh"
js_set_dev() {
    local field=$1 val=$2
    JSET_BUF="${JSET_BUF}${field}$(printf '\037')${val}$(printf '\036')"
}

js_set_dev_flush() {
    [ -z "$JSET_BUF" ] && return 0
    local SEP_REC="$(printf '\036')"
    local SEP_KV="$(printf '\037')"
    local rec k v keys_csv=""
    local _buf="$JSET_BUF"
    JSET_BUF=""
    set --
    while [ -n "$_buf" ]; do
        rec="${_buf%%${SEP_REC}*}"
        _buf="${_buf#*${SEP_REC}}"
        [ -z "$rec" ] && continue
        k="${rec%%${SEP_KV}*}"
        v="${rec#*${SEP_KV}}"
        set -- "$@" "$k" "$v"
        if [ -z "$keys_csv" ]; then keys_csv="$k"
        else keys_csv="$keys_csv,$k"
        fi
    done
    [ $# -eq 0 ] && return 0
    local out rc
    out=$(sh "$BATCH_HELPER" device "$MAC" "$@" 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        log "WARN: js_set_dev_flush failed rc=$rc keys=$keys_csv out=$out"
        if [ -z "$JSON_FAILED" ]; then JSON_FAILED="$keys_csv"
        else JSON_FAILED="$JSON_FAILED,$keys_csv"
        fi
        return 1
    fi
    return 0
}

. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    gate_lock()   { return 0; }
    gate_unlock() { return 0; }
}

valid_mac() {
    printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$'
}
valid_ipv4() {
    printf '%s' "$1" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}
valid_nonneg_num() {
    printf '%s' "$1" | grep -Eq '^[0-9]+(\.[0-9]+)?$'
}

# ── main ─────────────────────────────────────────────────────────

CMD=$1
MAC=$2
shift 2

if ! valid_mac "$MAC"; then
    emit_err "invalid mac: $MAC"
fi

has_device_or_v6_online() {
    local _m _if="${2:-}" _n6
    _m=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    if [ -f "$DEVICES" ] && tr -d '\r\n' < "$DEVICES" 2>/dev/null | tr 'A-Z' 'a-z' | grep -qF "\"$_m\""; then
        return 0
    fi
    if [ -s "$HNC_DIR/run/devices.flat" ] && tr 'A-Z' 'a-z' < "$HNC_DIR/run/devices.flat" 2>/dev/null | grep -qF "$_m"; then
        return 0
    fi
    if [ -n "$_if" ] && command -v ip >/dev/null 2>&1; then
        _n6=$(ip -6 neigh show dev "$_if" 2>/dev/null)
        [ -z "$_n6" ] && _n6=$(ip neigh show dev "$_if" 2>/dev/null)
        if printf '%s\n' "$_n6" | awk -v m="$_m" 'tolower($0) ~ ("lladdr " m) && $1 ~ /:/ && $NF != "FAILED" && $NF != "INCOMPLETE" {found=1; exit} END{exit !found}'; then
            return 0
        fi
    fi
    return 1
}

is_mac_blacklisted() {
    local _m
    [ -f "$RULES" ] || return 1
    _m=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    tr -d '\r\n' < "$RULES" 2>/dev/null | grep -oiE '"blacklist"[[:space:]]*:[[:space:]]*\[[^]]*\]' \
        | tr 'A-Z' 'a-z' | grep -qF "\"$_m\""
}

case "$CMD" in
    limit)
        DN_MBPS=$1
        UP_MBPS=$2
        [ -z "$DN_MBPS" ] && DN_MBPS=0
        [ -z "$UP_MBPS" ] && UP_MBPS=0
        if ! valid_nonneg_num "$DN_MBPS" || ! valid_nonneg_num "$UP_MBPS"; then
            emit_err "invalid rate: down='$DN_MBPS' up='$UP_MBPS' (expected non-negative number)"
        fi
        IP=$(get_ip "$MAC")
        IFACE=$(sh "$DETECT" iface 2>/dev/null)
        if [ -z "$IP" ] && ! has_device_or_v6_online "$MAC" "$IFACE"; then
            emit_err "device not found in devices.json (mac=$MAC, 设备可能离线或还没被探到)"
        fi
        if [ -z "$IFACE" ] || { [ "$IFACE" = "wlan0" ] && ! is_authoritative_wlan0_ap; }; then
            emit_err "no active hotspot iface (got '$IFACE')"
        fi
        gate_lock || emit_err "gate_lock timeout (5s), another global op in progress"
        if ! MID=$(get_or_assign_mid "$MAC"); then
            gate_unlock
            emit_err "mark_id exhausted; too many devices with persistent rules"
        fi
        if ! sh "$JSON_SET" device "$MAC" mark_id "$MID" >> "$LOG" 2>&1; then
            gate_unlock
            emit_err "failed to write mark_id=$MID to rules.json (mid alloc race risk)"
        fi
        sh "$JSON_SET" device "$MAC" last_seen_persist "$(now_ts)" >> "$LOG" 2>&1 || log "WARN: failed to update last_seen_persist for $MAC"
        gate_unlock
        log "limit mac=$MAC ip=${IP:-(v6-only)} mid=$MID dn=${DN_MBPS}mbps up=${UP_MBPS}mbps iface=$IFACE"
        # 1. iptables mark (纯 IPv6 设备无 IPv4 时传 "-" 挂载 L2 MAC + IPv6 下行正交标记)
        sh "$IPT" mark "${IP:--}" "$MAC" "$MID" >> "$LOG" 2>&1 \
            || emit_err "iptables mark failed (mid=$MID, see apply.log)"
        # 2. tc set_limit (内部在 HNC_MARK 已就位后同步执行一次 v6_sync.sh, 无需下方再次重复派发)
        TC_OUT=$(HNC_CLIENT_MAC="$MAC" sh "$TC" set_limit "$IFACE" "$MID" "$DN_MBPS" "$UP_MBPS" "$IP" 2>&1)
        TC_RC=$?
        [ -n "$TC_OUT" ] && log "tc set_limit output rc=$TC_RC: $TC_OUT"
        [ -x "$HNC_DIR/bin/hnc_clsact_sync.sh" ] && \
            sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG" 2>&1 || true
        if [ $TC_RC -ne 0 ] && [ $TC_RC -ne 8 ]; then
            log "tc set_limit failed, rolling back iptables mark (mid=$MID)"
            sh "$IPT" unmark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "rollback iptables unmark warn (mid=$MID)"
            emit_err "tc set_limit failed"
        fi
        PARTIAL_TC=""
        if [ $TC_RC -eq 8 ]; then
            PARTIAL_TC="uplink"
            UP_MBPS=0
            if ! num_gt0 "$DN_MBPS"; then
                log "tc set_limit partial rc=8 with down=0 -> effective 0/0 limit; rolling back (mac=$MAC mid=$MID)"
                DELAY_ENABLED=$(sh "$JSON_SET" device_get "$MAC" delay_enabled 2>/dev/null)
                DELAY_MS=$(sh "$JSON_SET" device_get "$MAC" delay_ms 2>/dev/null)
                JITTER_MS=$(sh "$JSON_SET" device_get "$MAC" jitter_ms 2>/dev/null)
                LOSS_PCT=$(sh "$JSON_SET" device_get "$MAC" loss_pct 2>/dev/null)
                HAS_DELAY=0
                [ "$DELAY_ENABLED" = "true" ] && HAS_DELAY=1
                num_gt0 "$DELAY_MS" && HAS_DELAY=1
                num_gt0 "$JITTER_MS" && HAS_DELAY=1
                num_gt0 "$LOSS_PCT" && HAS_DELAY=1
                _CID_CHK="$MID"; [ "$MID" = "1" ] && _CID_CHK=100
                HAS_SUBCLASS=0
                if [ -n "$IFACE" ]; then
                    grep -qx "$IFACE $_CID_CHK" "$HNC_DIR/run/app_qos.state" 2>/dev/null && HAS_SUBCLASS=1
                    grep -qx "$IFACE $_CID_CHK" "$HNC_DIR/run/app_limits.devs" 2>/dev/null && HAS_SUBCLASS=1
                fi
                if [ "$HAS_DELAY" = "0" ] && [ "$HAS_SUBCLASS" = "0" ]; then
                    sh "$TC" remove "$IFACE" "$MID" >> "$LOG" 2>&1 || true
                    sh "$IPT" unmark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "rollback iptables unmark warn (mid=$MID)"
                    is_mac_blacklisted "$MAC" || notify_offload "$MAC" 0
                fi
                [ -n "$IP" ] && js_set_dev ip "$IP"
                js_set_dev down_mbps 0
                js_set_dev up_mbps 0
                js_set_dev limit_enabled false
                js_set_dev last_seen_persist "$(now_ts)"
                js_set_dev_flush
                [ -x "$HNC_DIR/bin/hnc_clsact_sync.sh" ] && \
                    sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG" 2>&1 || true
                emit_err "uplink shaping unsupported on this kernel/ROM and downlink limit is 0"
            fi
            log "tc set_limit partial: uplink failed, downlink kept (mac=$MAC mid=$MID)"
        fi
        notify_offload "$MAC" 1
        [ -s "$HNC_DIR/data/app_limits.flat" ] && : > "$HNC_DIR/run/app_limit.dirty" 2>/dev/null || true
        # 3. 写 rules.json
        [ -n "$IP" ] && js_set_dev ip "$IP"
        js_set_dev down_mbps "$DN_MBPS"
        js_set_dev up_mbps "$UP_MBPS"
        js_set_dev limit_enabled true
        js_set_dev last_seen_persist "$(now_ts)"
        js_set_dev_flush
        if [ -n "$JSON_FAILED" ]; then
            log "limit applied (tc/iptables OK) but partial JSON write failed: $JSON_FAILED"
            echo "error: partial_json_fail=$JSON_FAILED"
            exit 8
        else
            if [ -n "$PARTIAL_TC" ]; then
                log "limit applied with partial tc warning: $PARTIAL_TC"
                echo "ok partial_tc_fail=$PARTIAL_TC"
            else
                log "limit applied OK"
                echo "ok"
            fi
        fi
        ;;

    alloc_mid)
        IP=$(get_ip "$MAC")
        if [ -z "$IP" ]; then
            _am_if=$(sh "$DETECT" iface 2>/dev/null)
            if ! has_device_or_v6_online "$MAC" "$_am_if"; then
                emit_err "device not found in devices.json (mac=$MAC)"
            fi
        fi
        gate_lock || emit_err "gate_lock timeout (5s)"
        if ! MID=$(get_or_assign_mid "$MAC"); then
            gate_unlock
            emit_err "mark_id exhausted; too many devices with persistent rules"
        fi
        if ! sh "$JSON_SET" device "$MAC" mark_id "$MID" >> "$LOG" 2>&1; then
            gate_unlock
            emit_err "failed to write mark_id=$MID to rules.json (mid alloc race risk)"
        fi
        sh "$JSON_SET" device "$MAC" last_seen_persist "$(now_ts)" >> "$LOG" 2>&1 || log "WARN: failed to update last_seen_persist for $MAC"
        gate_unlock
        log "alloc_mid mac=$MAC ip=${IP:-(v6-only)} mid=$MID"
        sh "$IPT" mark "${IP:--}" "$MAC" "$MID" >> "$LOG" 2>&1 \
            || emit_err "iptables mark failed (mid=$MID)"
        echo "$MID"
        ;;

    clear)
        IP=$(get_ip "$MAC")
        IFACE=$(sh "$DETECT" iface 2>/dev/null)
        MID=$(sh "$JSON_SET" device_get "$MAC" mark_id 2>/dev/null)
        if [ -z "$MID" ] || ! echo "$MID" | grep -qE '^[0-9]+$'; then
            log "clear mac=$MAC: no existing mid, skipping tc/iptables (nothing to clear)"
            js_set_dev down_mbps 0
            js_set_dev up_mbps 0
            js_set_dev limit_enabled false
            js_set_dev_flush
            mkdir -p "$HNC_DIR/run" 2>/dev/null || true
            : > "$HNC_DIR/run/app_limit.dirty" 2>/dev/null || true
            if [ -n "$JSON_FAILED" ]; then
                log "clear mac=$MAC (no-mid path) partial JSON write failed: $JSON_FAILED"
                echo "error: partial_json_fail=$JSON_FAILED"
                exit 8
            else
                echo "ok"
            fi
            exit 0
        fi
        log "clear mac=$MAC ip=$IP mid=$MID iface=$IFACE"
        DELAY_ENABLED=$(sh "$JSON_SET" device_get "$MAC" delay_enabled 2>/dev/null)
        DELAY_MS=$(sh "$JSON_SET" device_get "$MAC" delay_ms 2>/dev/null)
        JITTER_MS=$(sh "$JSON_SET" device_get "$MAC" jitter_ms 2>/dev/null)
        LOSS_PCT=$(sh "$JSON_SET" device_get "$MAC" loss_pct 2>/dev/null)
        HAS_DELAY=0
        [ "$DELAY_ENABLED" = "true" ] && HAS_DELAY=1
        num_gt0 "$DELAY_MS" && HAS_DELAY=1
        num_gt0 "$JITTER_MS" && HAS_DELAY=1
        num_gt0 "$LOSS_PCT" && HAS_DELAY=1

        _CID_CHK="$MID"; [ "$MID" = "1" ] && _CID_CHK=100
        HAS_SUBCLASS=0
        if [ -n "$IFACE" ]; then
            grep -qx "$IFACE $_CID_CHK" "$HNC_DIR/run/app_qos.state" 2>/dev/null && HAS_SUBCLASS=1
            grep -qx "$IFACE $_CID_CHK" "$HNC_DIR/run/app_limits.devs" 2>/dev/null && HAS_SUBCLASS=1
        fi

        if [ "$HAS_DELAY" = "1" ] || [ "$HAS_SUBCLASS" = "1" ]; then
            if [ -n "$IFACE" ] && { [ "$IFACE" != "wlan0" ] || is_authoritative_wlan0_ap; }; then
                HNC_CLIENT_MAC="$MAC" sh "$TC" set_limit "$IFACE" "$MID" 0 0 "$IP" >> "$LOG" 2>&1 \
                    || log "tc set_limit clear-rate warn (mid=$MID, delay preserved)"
            else
                log "clear warn: no active iface, preserved iptables mark because delay is still enabled"
            fi
            log "clear limit only: delay/netem preserved (mac=$MAC mid=$MID)"
        else
            if [ -n "$IFACE" ] && { [ "$IFACE" != "wlan0" ] || is_authoritative_wlan0_ap; }; then
                sh "$TC" remove "$IFACE" "$MID" >> "$LOG" 2>&1 || log "tc remove warn (mid=$MID may not be applied)"
            fi
            is_mac_blacklisted "$MAC" || notify_offload "$MAC" 0
            UNMARK_IP=$IP
            [ -n "$UNMARK_IP" ] || UNMARK_IP=$(get_rule_ip "$MAC")
            valid_ipv4 "$UNMARK_IP" || UNMARK_IP=""
            sh "$IPT" unmark "$UNMARK_IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "iptables unmark warn"
        fi
        js_set_dev down_mbps 0
        js_set_dev up_mbps 0
        js_set_dev limit_enabled false
        js_set_dev_flush
        # 触发 apply_app_limits 重算并抬高单应用 1:9eXX 兜底 ceil(消除旧整机限速 ceil 残留钳制)
        mkdir -p "$HNC_DIR/run" 2>/dev/null || true
        : > "$HNC_DIR/run/app_limit.dirty" 2>/dev/null || true
        if [ -n "$JSON_FAILED" ]; then
            log "clear applied (tc/iptables OK) but partial JSON write failed: $JSON_FAILED"
            echo "error: partial_json_fail=$JSON_FAILED"
            exit 8
        else
            log "clear OK"
            echo "ok"
        fi
        ;;

    bl_add)
        IP=$(get_ip "$MAC")
        OLD_BLOCKED_IP=$(get_blocked_ip "$MAC")
        log "bl_add mac=$MAC ip=${IP:-(no-ip)} old_blocked_ip=${OLD_BLOCKED_IP:-(none)}"
        if [ -n "$IP" ]; then
            if [ -n "$OLD_BLOCKED_IP" ] && [ "$OLD_BLOCKED_IP" != "$IP" ]; then
                sh "$IPT" blacklist_remove "$OLD_BLOCKED_IP" "$MAC" >> "$LOG" 2>&1 || true
            fi
            sh "$IPT" blacklist_add "$IP" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (see apply.log)"
        else
            sh "$IPT" blacklist_add "" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (mac-only path, see apply.log)"
        fi
        # 通知 offload 调度器立即压制并踢除该 MAC 的硬件快路径存量流, 使其回落软件 FORWARD/HNC_CTRL 阻断
        notify_offload "$MAC" 1
        _bl_json_ok=1
        sh "$JSON_SET" bl_add "$MAC" >/dev/null 2>&1 || _bl_json_ok=0
        if [ -n "$IP" ]; then
            sh "$JSON_SET" device "$MAC" blocked_ip "$IP" >> "$LOG" 2>&1 || _bl_json_ok=0
        fi
        if [ "$_bl_json_ok" = "1" ]; then
            if [ -f "$HNC_DIR/bin/hnc_clsact_sync.sh" ]; then
                sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG" 2>&1 || true
            fi
            log "bl_add OK"
            echo "ok"
        else
            log "bl_add applied to iptables but JSON bl_add/blocked_ip failed"
            echo "error: partial_json_fail=blacklist_add"
            exit 8
        fi
        ;;

    bl_del)
        LIVE_IP=$(get_ip "$MAC")
        BLOCKED_IP=$(get_blocked_ip "$MAC")
        IP="$LIVE_IP"
        [ -z "$IP" ] && IP="$BLOCKED_IP"
        [ -z "$IP" ] && IP=$(get_rule_ip "$MAC")
        valid_ipv4 "$IP" || IP=""
        log "bl_del mac=$MAC ip=${IP:-(no-ip)} blocked_ip=${BLOCKED_IP:-(none)}"
        if [ -n "$IP" ]; then
            sh "$IPT" blacklist_remove "$IP" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (rule may not exist)"
        else
            sh "$IPT" blacklist_remove "" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (mac-only path)"
        fi
        if [ -n "$BLOCKED_IP" ] && [ "$BLOCKED_IP" != "$IP" ]; then
            sh "$IPT" blacklist_remove "$BLOCKED_IP" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove old blocked_ip=$BLOCKED_IP warn"
        fi
        if sh "$JSON_SET" bl_del "$MAC" >/dev/null 2>&1; then
            if [ -n "$BLOCKED_IP" ]; then
                sh "$JSON_SET" device "$MAC" blocked_ip "" >> "$LOG" 2>&1 \
                    || log "WARN: failed to clear blocked_ip for $MAC"
            fi
            if [ -f "$HNC_DIR/bin/hnc_clsact_sync.sh" ]; then
                sh "$HNC_DIR/bin/hnc_clsact_sync.sh" >> "$LOG" 2>&1 || true
            fi
            _bl_le=$(sh "$JSON_SET" device_get "$MAC" limit_enabled 2>/dev/null)
            _bl_de=$(sh "$JSON_SET" device_get "$MAC" delay_enabled 2>/dev/null)
            if [ "$_bl_le" != "true" ] && [ "$_bl_de" != "true" ]; then
                notify_offload "$MAC" 0
            fi
            log "bl_del OK"
            echo "ok"
        else
            log "bl_del applied to iptables but JSON bl_del failed"
            echo "error: partial_json_fail=blacklist_del"
            exit 8
        fi
        ;;

    *)
        emit_err "unknown cmd: $CMD (expected: limit|alloc_mid|clear|bl_add|bl_del)"
        ;;
esac
