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
get_or_assign_mid() {
    local mac=$1
    local existing
    # 用 awk 提取 devices 里的 mark_id
    existing=$(awk -v m="$mac" '
    {
        idx = index($0, "\"" m "\"")
        if (idx > 0) {
            tail = substr($0, idx)
            if (match(tail, /"mark_id"[[:space:]]*:[[:space:]]*[0-9]+/)) {
                seg = substr(tail, RSTART, RLENGTH)
                if (match(seg, /[0-9]+$/)) {
                    print substr(seg, RSTART, RLENGTH)
                    exit
                }
            }
        }
    }
    ' "$RULES" 2>/dev/null)
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
    # 哈希起点 = last byte % 99 + 1, 覆盖完整 1..99 mark_id 池。
    local lb=$(echo "$mac" | awk -F: '{print $6}')
    # base16 → dec
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
    # v5.1.0-rc1 hotfix: mark_id 用尽时必须失败,不能回退复用 start。
    log "ERROR: mark_id exhausted for mac=$mac (all 1..99 are used)"
    return 1
}

# ── helper: 累计 json_set 失败 (rc3.1.33 修 #18) ─────────────────
# 之前 limit/clear 8 处 `sh json_set ... >/dev/null 2>&1` 全静默, 任何一次写
# rules.json 失败 → iptables/tc 装好但 JSON 半状态 → 重启后 watchdog
# restore_rules grep MAC 找不到 mark_id → continue → 限速规则永久丢失
# (但 iptables 链残留旧规则 → UI 显示"未限速"/实际仍被限速 split-brain).
#
# 仿照 daemon/hnc_httpd/action_v5.go set_delay 的 failed[] 累计模式:
# 不 fail 调用 (tc/iptables 已应用回滚意义不大), 但 log WARN + 在 stdout
# 追加 partial_json_fail 字段, Go 端能识别并提示用户重试收敛.
JSON_FAILED=""
JSET_BUF=""
BATCH_HELPER="$HNC_DIR/bin/json_set_batch.sh"
# rc5.1.1: buffer 模式. 不立即写, 等 flush 一次性 batch 写入.
# 兼容原签名: js_set_dev <field> <value>
js_set_dev() {
    local field=$1 val=$2
    # 用 ASCII 0x1F 分隔 K 与 V, 0x1E 分隔 record
    JSET_BUF="${JSET_BUF}${field}$(printf '\037')${val}$(printf '\036')"
}

# rc5.1.1: 一次写入所有缓冲字段. limit/clear 在最后调一次.
js_set_dev_flush() {
    [ -z "$JSET_BUF" ] && return 0
    # 1. 把 buffer 切成 K V K V ... 给 batch helper
    local args=""
    local SEP_REC="$(printf '\036')"
    local SEP_KV="$(printf '\037')"
    local rec k v
    # 用 while + IFS 拆分, 兼容 ash
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
    # 2. 调用 batch helper 一次写入
    local out rc
    # shellcheck disable=SC2086
    out=$(sh "$BATCH_HELPER" device "$MAC" $args 2>&1)
    rc=$?
    if [ $rc -ne 0 ]; then
        log "WARN: js_set_dev_flush failed rc=$rc args=$args out=$out"
        # 把所有缓冲过的字段名都加进 JSON_FAILED
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

# rc3.1.33 修 #19: get_or_assign_mid 在 gate_lock 保护下跑.
# 之前两个并发 limit (用户在 WebUI 同时对两台设备点"应用限速") 都看到 mark_id 5
# 空着 → 都返回 5 → 两个不同 MAC 共用同一 mark_id → tc class 冲突 / iptables
# 互相 mask / 流量计数混乱. gate_lock 持有期 ~ms 级, 影响最小.
#
# clear 路径不加锁 (mark_id 已存在, get_or_assign_mid 走第一分支直接 echo,
# 不进 alloc 探测循环).
. "$HNC_DIR/bin/hnc_lock.sh" 2>/dev/null || {
    # hnc_lock.sh 不可用时降级为无锁 (跟 iptables_manager.sh 同策略)
    gate_lock()   { return 0; }
    gate_unlock() { return 0; }
}

# v5.8.8 (audit): 白名单校验进 tc/iptables 的外部字段(防御纵深)。
# MAC 来自 /api/action(经鉴权但仍是外部输入);IP 由 get_ip 从 devices.json 读
# (源头含 DHCP option12/mDNS 任意字节)。变量拼接处均已带引号、无 eval,故非命令
# 注入;此处再做格式白名单,异常输入直接拒,绝不让怪字符进 tc/iptables 参数。
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

# 所有动作都以 MAC 为键;格式不合法直接拒(合法 MAC 必过,怪字符必拒)。
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
        # rc3.1.33 修 #19: 在 gate_lock 内 alloc + 立即写 mark_id, 防并发分配冲突
        gate_lock || emit_err "gate_lock timeout (5s), another global op in progress"
        if ! MID=$(get_or_assign_mid "$MAC"); then
            gate_unlock
            emit_err "mark_id exhausted; too many devices with persistent rules"
        fi
        # 立即写 mark_id 到 rules.json, 让其他并发 alloc 看到这个 mid 已被占用
        # (get_or_assign_mid 下一次扫 rules.json 会把它纳入 used 集合).
        # 这一处用 sh 直接调而不是 js_set_dev, 因为失败要立即 abort 整个 limit.
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
        # 2. tc set_limit
        # hotfix6: capture tc_manager output so partial uplink failure can still keep
        # a working downlink limit. This avoids UI freeze/fail on ColorOS IFB/mirred
        # races when the user sets both download and upload rates.
        TC_OUT=$(sh "$TC" set_limit "$IFACE" "$MID" "$DN_MBPS" "$UP_MBPS" "$IP" 2>&1)
        TC_RC=$?
        [ -n "$TC_OUT" ] && log "tc set_limit output rc=$TC_RC: $TC_OUT"
        if [ $TC_RC -ne 0 ] && [ $TC_RC -ne 8 ]; then
            # hotfix5: avoid half-applied state. The mark was already installed, but
            # rules.json has not been updated yet; remove the packet mark so traffic
            # is not left classified into a failed/partial tc setup.
            log "tc set_limit failed, rolling back iptables mark (mid=$MID)"
            sh "$IPT" unmark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "rollback iptables unmark warn (mid=$MID)"
            emit_err "tc set_limit failed"
        fi
        PARTIAL_TC=""
        if [ $TC_RC -eq 8 ]; then
            # Downlink was applied but uplink IFB/mirred failed. Persist only the
            # actually-applied downlink rate so UI and restore do not lie about uplink.
            PARTIAL_TC="uplink"
            UP_MBPS=0
            log "tc set_limit partial: uplink failed, downlink kept (mac=$MAC mid=$MID)"
        fi
        # v5.0: tc 规则就位, 通知 scheduler 决定是否触发 BPF offload disable
        notify_offload "$MAC" 1
        # 3. 写 rules.json (mark_id 已经在 gate_lock 内写过了, 这里只写其他字段)
        # rc3.1.33 修 #18: js_set_dev 累计失败, 不 fail 但 log + 报告
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
        # rc2 修 G3: 只分配 mark_id + iptables mark, 不触 tc / 不写 limit_enabled
        # 用途: delay_set 需要 mid 把包分流到 netem class, 但不想污染 limit 状态.
        # 之前 actionDelaySet 借用 "limit 0 0" 分配 mid, 副作用:
        #   rules.json 被写成 limit_enabled=true, down_mbps=0, up_mbps=0
        #   → UI 显示"已限速到 0", 用户误解 / 下次 restore 行为乱
        # 幂等: get_or_assign_mid 已分配过直接返回旧值, iptables mark_device 自带
        #       -D 后 -A 清理, 重复调用无副作用. stdout 只出 mid (整数, 供 caller 取).
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
        # stdout 纯净给 Go caller 用 strconv.Itoa 解析
        echo "$MID"
        ;;

    clear)
        IP=$(get_ip "$MAC")
        IFACE=$(sh "$DETECT" iface 2>/dev/null)
        # rc2 修 S12: clear 之前先 device_get 看是否有 mid, 没有就不调 get_or_assign_mid
        # (避免给 "从未限速过的设备" 分配一个立刻丢弃的 mid — 99 个 mid 很稀缺).
        MID=$(sh "$JSON_SET" device_get "$MAC" mark_id 2>/dev/null)
        if [ -z "$MID" ] || ! echo "$MID" | grep -qE '^[0-9]+$'; then
            log "clear mac=$MAC: no existing mid, skipping tc/iptables (nothing to clear)"
            # 即便没 mid, 也把 limit_enabled 归位, 保证 rules.json 一致
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
        # v5.1.0-rc1 hotfix: clear 是“清限速”,不能误删 delay/netem。
        # 如果 delay/jitter/loss 仍启用,只把 HTB rate 复位为默认,保留 class、netem、iptables mark 和 offload disable。
        DELAY_ENABLED=$(sh "$JSON_SET" device_get "$MAC" delay_enabled 2>/dev/null)
        DELAY_MS=$(sh "$JSON_SET" device_get "$MAC" delay_ms 2>/dev/null)
        JITTER_MS=$(sh "$JSON_SET" device_get "$MAC" jitter_ms 2>/dev/null)
        LOSS_PCT=$(sh "$JSON_SET" device_get "$MAC" loss_pct 2>/dev/null)
        HAS_DELAY=0
        [ "$DELAY_ENABLED" = "true" ] && HAS_DELAY=1
        num_gt0 "$DELAY_MS" && HAS_DELAY=1
        num_gt0 "$JITTER_MS" && HAS_DELAY=1
        num_gt0 "$LOSS_PCT" && HAS_DELAY=1

        if [ "$HAS_DELAY" = "1" ]; then
            if [ -n "$IFACE" ] && [ "$IFACE" != "wlan0" ]; then
                sh "$TC" set_limit "$IFACE" "$MID" 0 0 "$IP" >> "$LOG" 2>&1 \
                    || log "tc set_limit clear-rate warn (mid=$MID, delay preserved)"
            else
                log "clear warn: no active iface, preserved iptables mark because delay is still enabled"
            fi
            log "clear limit only: delay/netem preserved (mac=$MAC mid=$MID)"
        else
            # 没有 delay 时才允许完整删除 TC class/filter/qdisc 和 iptables mark。
            if [ -n "$IFACE" ] && [ "$IFACE" != "wlan0" ]; then
                sh "$TC" remove "$IFACE" "$MID" >> "$LOG" 2>&1 || log "tc remove warn (mid=$MID may not be applied)"
            fi
            # v5.0: tc 规则已清, 通知 scheduler 可能恢复 offload
            notify_offload "$MAC" 0
            if [ -n "$IP" ]; then
                sh "$IPT" unmark "$IP" "$MAC" "$MID" >> "$LOG" 2>&1 || log "iptables unmark warn"
            fi
        fi
        # 3. 写 rules.json: 清空 down_mbps/up_mbps + limit_enabled=false
        # rc3.1.33 修 #18: 累计失败. 如果 limit_enabled 写失败但 tc 已清, 下次 watchdog
        # restore 会用 limit_enabled=true 老值重新装规则 (用户看到限速复活), 必须报告.
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
        # 加黑: iptables blacklist_add + json_set.sh bl_add
        # IP 可能为空(设备已离线),iptables 没 IP 就只挂 MAC drop 规则,仍然有效
        IP=$(get_ip "$MAC")
        log "bl_add mac=$MAC ip=${IP:-(no-ip)}"
        # rc3.1.34 修 #23: 之前 `${IP:-0.0.0.0}` 在离线设备 IP 为空时传字面 0.0.0.0
        # 给 iptables_manager.sh, 装出垃圾规则 `-s 0.0.0.0 -m mac --mac-source ...`,
        # 实际 0.0.0.0 不会匹配任何流量, 但污染 iptables 链 + GC 规则时多余处理.
        # 改成: IP 空时显式传空串, iptables_manager.sh blacklist_add 已有兜底
        # (只挂 MAC-only 规则). 跟 bl_del 用同样模式确保对称.
        if [ -n "$IP" ]; then
            sh "$IPT" blacklist_add "$IP" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (see apply.log)"
        else
            sh "$IPT" blacklist_add "" "$MAC" >> "$LOG" 2>&1 \
                || emit_err "iptables blacklist_add failed (mac-only path, see apply.log)"
        fi
        # 2. json: bl_add 维护 blacklist 数组
        # hotfix2: 不再忽略 JSON 写失败,避免 iptables 已生效但重启后状态丢失。
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
        # rc3.1.34 修 #23: 同 bl_add, 不传 0.0.0.0 字面值
        if [ -n "$IP" ]; then
            sh "$IPT" blacklist_remove "$IP" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (rule may not exist)"
        else
            sh "$IPT" blacklist_remove "" "$MAC" >> "$LOG" 2>&1 \
                || log "iptables blacklist_remove warn (mac-only path)"
        fi
        # 2. json
        # hotfix2: 不再忽略 JSON 写失败,避免 UI/持久化状态与 iptables 不一致。
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
