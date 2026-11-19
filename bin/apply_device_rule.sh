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

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && \
    export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

HNC_DIR=${HNC_DIR:-/data/local/hnc}
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
    # 简单 grep + sed: 找 "<mac>": { ... "ip": "x.x.x.x" ... }
    # devices.json 是单行 JSON, 找 mac 后 60 字符内的 "ip":"..."
    local _ip
    _ip=$(awk -v m="$mac" '
    BEGIN { found=0 }
    {
        idx = index($0, "\"" m "\"")
        if (idx > 0) {
            tail = substr($0, idx)
            if (match(tail, /"ip"[[:space:]]*:[[:space:]]*"[0-9.]+"/)) {
                seg = substr(tail, RSTART, RLENGTH)
                if (match(seg, /[0-9.]+/)) {
                    print substr(seg, RSTART, RLENGTH)
                    found=1
                    exit
                }
            }
        }
    }
    END { if (!found) print "" }
    ' "$DEVICES")
    # v5.8.8 (audit): 只回合法 IPv4,挡掉 1.2.3.4.5 这类畸形(awk 已限 [0-9.]、不可注入,
    # 这里再保证四段合法八位组),否则返回空,调用方按"无 IP"处理。
    if valid_ipv4 "$_ip"; then printf '%s\n' "$_ip"; else echo ""; fi
}

# rules.json fallback IP, used when the device is offline but old IP-specific
# iptables DROP/MARK rules need cleanup.
get_rule_ip() {
    local mac=$1
    sh "$JSON_SET" device_get "$mac" ip 2>/dev/null | awk 'NR==1{print; exit}'
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
    local args=""
    local SEP_REC="$(printf '\036')"
    local SEP_KV="$(printf '\037')"
    local rec k v
    local _buf="$JSET_BUF"
    JSET_BUF=""
    while [ -n "$_buf" ]; do
        rec="${_buf%%${SEP_REC}*}"
        _buf="${_buf#*${SEP_REC}}"
        [ -z "$rec" ] && continue
        k="${rec%%${SEP_KV}*}"
        v="${rec#*${SEP_KV}}"
        args="$args $k $v"
    done
    local out rc
    # shellcheck disable=SC2086
    out=$(sh "$BATCH_HELPER" device "$MAC" $args 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        log "WARN: js_set_dev_flush failed rc=$rc args=$args out=$out"
        local kk
        set -- $args
        while [ $# -ge 2 ]; do
            kk=$1; shift 2
            if [ -z "$JSON_FAILED" ]; then JSON_FAILED="$kk"
            else JSON_FAILED="$JSON_FAILED,$kk"
            fi
        done
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

# ── main ─────────────────────────────────────────────────────────

CMD=$1
MAC=$2
shift 2

if ! valid_mac "$MAC"; then
    emit_err "invalid mac: $MAC"
fi

case "$CMD" in
    limit)
        DN_MBPS=$1
        UP_MBPS=$2
        [ -z "$DN_MBPS" ] && DN_MBPS=0
        [ -z "$UP_MBPS" ] && UP_MBPS=0
        IP=$(get_ip "$MAC")
        if [ -z "$IP" ]; then
            emit_err "device not found in devices.json (mac=$MAC, 设备可能离线或还没被探到)"
        fi
        IFACE=$(sh "$DETECT" iface 2>/dev/null)
        if [ -z "$IFACE" ] || [ "$IFACE" = "wlan0" ]; then
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
        log "limit mac=$MAC ip=$IP mid=$MID dn=${DN_MBPS}mbps up=${UP_MBPS}mbps iface=$IFACE"
        # 1. iptables mark
        sh "$IPT" mark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 \
            || emit_err "iptables mark failed (mid=$MID, see apply.log)"
        # 2. tc set_limit (内部在 HNC_MARK 已就位后同步执行一次 v6_sync.sh, 无需下方再次重复派发)
        TC_OUT=$(sh "$TC" set_limit "$IFACE" "$MID" "$DN_MBPS" "$UP_MBPS" "$IP" 2>&1)
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
            log "tc set_limit partial: uplink failed, downlink kept (mac=$MAC mid=$MID)"
        fi
        notify_offload "$MAC" 1
        [ -s "$HNC_DIR/data/app_limits.flat" ] && : > "$HNC_DIR/run/app_limit.dirty" 2>/dev/null || true
        # 3. 写 rules.json
        js_set_dev ip "$IP"
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
            emit_err "device not found in devices.json (mac=$MAC)"
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
        log "alloc_mid mac=$MAC ip=$IP mid=$MID"
        sh "$IPT" mark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 \
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
            if [ -n "$IFACE" ] && [ "$IFACE" != "wlan0" ]; then
                sh "$TC" set_limit "$IFACE" "$MID" 0 0 "$IP" >> "$LOG" 2>&1 \
                    || log "tc set_limit clear-rate warn (mid=$MID, delay preserved)"
            else
                log "clear warn: no active iface, preserved iptables mark because delay is still enabled"
            fi
            log "clear limit only: delay/netem preserved (mac=$MAC mid=$MID)"
        else
            if [ -n "$IFACE" ] && [ "$IFACE" != "wlan0" ]; then
                sh "$TC" remove "$IFACE" "$MID" >> "$LOG" 2>&1 || log "tc remove warn (mid=$MID may not be applied)"
            fi
            notify_offload "$MAC" 0
            UNMARK_IP=$IP
            [ -n "$UNMARK_IP" ] || UNMARK_IP=$(get_rule_ip "$MAC")
            valid_ipv4 "$UNMARK_IP" || UNMARK_IP=""
            sh "$IPT" unmark "$UNMARK_IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "iptables unmark warn"
        fi
        js_set_dev down_mbps 0
        js_set_dev up_mbps 0
        js_set_dev limit_enabled false
        js_set_dev_flush
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
        log "bl_add mac=$MAC ip=${IP:-(no-ip)}"
        if [ -n "$IP" ]; then
            sh "$IPT" blacklist_add "$IP" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (see apply.log)"
        else
            sh "$IPT" blacklist_add "" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (mac-only path, see apply.log)"
        fi
        if sh "$JSON_SET" bl_add "$MAC" >/dev/null 2>&1; then
            log "bl_add OK"
            echo "ok"
        else
            log "bl_add applied to iptables but JSON bl_add failed"
            echo "error: partial_json_fail=blacklist_add"
            exit 8
        fi
        ;;

    bl_del)
        IP=$(get_ip "$MAC")
        [ -z "$IP" ] && IP=$(get_rule_ip "$MAC")
        log "bl_del mac=$MAC ip=${IP:-(no-ip)}"
        if [ -n "$IP" ]; then
            sh "$IPT" blacklist_remove "$IP" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (rule may not exist)"
        else
            sh "$IPT" blacklist_remove "" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (mac-only path)"
        fi
        if sh "$JSON_SET" bl_del "$MAC" >/dev/null 2>&1; then
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
