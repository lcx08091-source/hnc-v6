#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
# rc13: 追加 /data/local/hnc/bin —— SukiSU 运行期卸 /system/bin 时,裸命令
# (sleep/sh/...) 会 fallthrough 到 service.sh 在 /data 预置的 applet 副本,不再 ENOENT 崩。
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:/data/local/hnc/bin:$PATH
# watchdog.sh — 规则完整性守护
#
# 【v3.4.1 核心修复】
#  v3.4.0 用 `ip monitor link route` 监听 netlink 事件，每次有
#  网络事件就触发 full_restore（拆掉整个 tc 树重建）。但 ip monitor
#  对 ARP 状态变化（REACHABLE/STALE/DELAY）、v6 RA、移动数据路由更新、
#  VPN 状态变化都会触发，结果在真机上每 10 秒就 full_restore 一次，
#  每次重建有 100-500ms 的"无限速"窗口，TCP 在窗口里被打断。
#  真机日志显示一次会话产生 158 次 RESTORE。
#
#  v3.4.1 修复：
#   1. 完全删除 ip monitor 事件触发，只靠 60s 周期 health check
#   2. iface 检测加 5 分钟缓存，避免 wlan0/wlan2 跳变误触发 restore
#   3. INTERVAL_RECOVERY 从 10s 改为 30s，避免连续重建
#   4. full_restore 前先确认 iface 有效，避免在错误接口上跑 init_tc
#
# v5.33: 「判断」(热点探测 / 规则健康 / 上行链路检查)只在 Go 看门狗里一份
# (src/dpid/cmd/hnc_watchdog/native.go); 本脚本只剩「动手」的 action。

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
fi
# v5.33: prune_duplicate_hotspotd(action prune_dup_hotspotd)与 service.sh 共用 bin/hnc_proc.sh
if [ -f "$HNC_DIR/bin/hnc_proc.sh" ]; then
    . "$HNC_DIR/bin/hnc_proc.sh"
elif [ -f "${0%/*}/hnc_proc.sh" ]; then
    . "${0%/*}/hnc_proc.sh"
fi
LOG=$HNC_DIR/logs/watchdog.log
RUN=$HNC_DIR/run

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [WDG] $1" >> "$LOG" 2>/dev/null || true
}

log_error() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [WDG] [ERROR] $1" >> "$LOG" 2>/dev/null || true
}

# capability-aware uplink gate. If capability_probe already proved
# IFB/mirred is unavailable, watchdog must not keep repairing ifb0/ingress.
watchdog_cap_bool_value() {
    local key=$1 cap="$RUN/capabilities.json"
    [ -f "$cap" ] || return 1
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*true" "$cap" 2>/dev/null; then
        echo true
        return 0
    fi
    if grep -Eq "\"${key}\"[[:space:]]*:[[:space:]]*false" "$cap" 2>/dev/null; then
        echo false
        return 0
    fi
    return 1
}

watchdog_cap_uplink_value() {
    watchdog_cap_bool_value uplink_supported
}

watchdog_cap_false() {
    [ "$(watchdog_cap_bool_value "$1" 2>/dev/null || echo unknown)" = "false" ]
}

watchdog_tc_core_supported() {
    # Current HNC limit/netem restore path is HTB-root based. If tc_htb=false,
    # watchdog must not keep trying init/restore loops. Unknown keeps legacy behavior.
    ! watchdog_cap_false tc_htb
}

watchdog_mark_tc_unsupported_once() {
    local kind=${1:-tc} once="$RUN/${kind}_unsupported_logged"
    if [ ! -f "$once" ]; then
        log "$kind unsupported by capabilities; skip tc init/restore health repair"
        echo 1 > "$once" 2>/dev/null || true
    fi
}

watchdog_mark_uplink_unsupported_once() {
    local now marker once
    now=$(date +%s 2>/dev/null || echo 0)
    marker="$RUN/uplink_unsupported"
    once="$RUN/uplink_unsupported_logged"
    [ -f "$marker" ] || printf '%s\n' "{\"ifb_unsupported\":true,\"since\":$now,\"reason\":\"capability_probe uplink_supported=false\"}" > "$marker" 2>/dev/null || true
    if [ ! -f "$once" ]; then
        log "ensure_tc_uplink: uplink_supported=false; skip IFB/mirred repair"
        echo 1 > "$once" 2>/dev/null || true
    fi
}

# Rerun capability probe once hotspot iface is ACTIVE (throttled to 6h per boot+iface).
CAP_PROBE_MIN_INTERVAL=21600
run_capability_probe_active() {
    local iface="$1" now last last_if
    [ -n "$iface" ] || return 0
    [ -x "$HNC_DIR/bin/capability_probe.sh" ] || return 0
    ip link show "$iface" >/dev/null 2>&1 || return 0

    now=$(date +%s 2>/dev/null || echo 0)
    read -r last last_if < "$RUN/capability_probe_last" 2>/dev/null
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    [ -n "$last_if" ] || last_if="$iface"
    local up boot_at
    up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    case "$up" in ''|*[!0-9]*) boot_at=0 ;; *) boot_at=$((now - up)) ;; esac
    if [ "$last_if" = "$iface" ] && [ "$last" -ge "$boot_at" ] 2>/dev/null \
       && [ "$now" -ge "$last" ] 2>/dev/null \
       && [ $((now - last)) -lt "$CAP_PROBE_MIN_INTERVAL" ] 2>/dev/null; then
        return 0
    fi

    echo "$iface" > "$RUN/iface.cache" 2>/dev/null || true
    echo "$now $iface" > "$RUN/capability_probe_last" 2>/dev/null || true
    log "capability_probe: running for active iface=$iface"
    HNC="$HNC_DIR" sh "$HNC_DIR/bin/capability_probe.sh" >> "$HNC_DIR/logs/capabilities.log" 2>&1 || \
        log "capability_probe: failed for iface=$iface"
}

# TC repair circuit breaker.
TC_REPAIR_OPEN_UNTIL="$RUN/tc_repair_open_until"
TC_REPAIR_FAIL_COUNT="$RUN/tc_repair_fail_count"
TC_REPAIR_FUSE_THRESHOLD=3
TC_REPAIR_FUSE_SEC=300

tc_repair_allowed() {
    local now until left
    now=$(date +%s 2>/dev/null || echo 0)
    until=$(cat "$TC_REPAIR_OPEN_UNTIL" 2>/dev/null || echo 0)
    if [ -n "$until" ] && [ "$until" -gt "$now" ] 2>/dev/null; then
        left=$((until - now))
        log "tc repair circuit open, skip auto restore for ${left}s"
        return 1
    fi
    return 0
}

tc_repair_record() {
    local ok=${1:-0} cnt now until
    if [ "$ok" = "1" ]; then
        rm -f "$TC_REPAIR_FAIL_COUNT" "$TC_REPAIR_OPEN_UNTIL" 2>/dev/null || true
        return 0
    fi
    cnt=$(cat "$TC_REPAIR_FAIL_COUNT" 2>/dev/null || echo 0)
    cnt=$((cnt + 1))
    echo "$cnt" > "$TC_REPAIR_FAIL_COUNT" 2>/dev/null || true
    if [ "$cnt" -ge "$TC_REPAIR_FUSE_THRESHOLD" ]; then
        now=$(date +%s 2>/dev/null || echo 0)
        until=$((now + TC_REPAIR_FUSE_SEC))
        echo "$until" > "$TC_REPAIR_OPEN_UNTIL" 2>/dev/null || true
        echo 0 > "$TC_REPAIR_FAIL_COUNT" 2>/dev/null || true
        log_error "tc repair failed ${cnt} times; circuit open for ${TC_REPAIR_FUSE_SEC}s"
    fi
}

# action 模式每次是独立短进程, 节流时间戳必须持久化在 $RUN/(tmpfs)而非进程内死变量!
LOG_ROTATE_INTERVAL=300
LAST_LOG_ROTATE_FILE="$RUN/wdg_last_log_rotate"
LAST_STALE_CLEANUP_FILE="$RUN/wdg_last_stale_cleanup_day"
STATE_FILE="$RUN/hnc_state"

rotate_logs_periodic() {
    local now last
    now=$(date +%s 2>/dev/null || echo 0)
    last=$(cat "$LAST_LOG_ROTATE_FILE" 2>/dev/null | tr -dc '0-9')
    [ -n "$last" ] || last=0
    if [ "$now" -lt "$last" ] || [ $((now - last)) -ge "$LOG_ROTATE_INTERVAL" ]; then
        sh "$HNC_DIR/bin/log_rotate.sh" check 2>/dev/null || true
        mkdir -p "$RUN" 2>/dev/null || true
        echo "$now" > "$LAST_LOG_ROTATE_FILE" 2>/dev/null || true
    fi
}

cleanup_stale_rules_daily() {
    local day last_day
    day=$(date +%Y%m%d 2>/dev/null) || day=unknown
    case "$(cat "$STATE_FILE" 2>/dev/null || echo PENDING)" in
        ACTIVE:*) ;;
        *) return 0 ;;
    esac
    last_day=$(cat "$LAST_STALE_CLEANUP_FILE" 2>/dev/null | tr -d ' \t\r\n')
    [ "$day" = "$last_day" ] && return 0
    [ -x "$HNC_DIR/bin/cleanup_stale_rules.sh" ] || return 0
    mkdir -p "$RUN" 2>/dev/null || true
    echo "$day" > "$LAST_STALE_CLEANUP_FILE" 2>/dev/null || true
    sh "$HNC_DIR/bin/cleanup_stale_rules.sh" >> "$HNC_DIR/logs/cleanup_stale.log" 2>&1 </dev/null >/dev/null &
    log "stale rules cleanup scheduled for day=$day"
}

# 信号中止必须返回非零退出码(143/130), 绝不能伪 exit 0 误导 Go 看门狗以为 action 成功!
WDG_CLEAN_EXIT=0
trap 'WDG_CLEAN_EXIT=1; log "received SIGTERM, aborting action"; exit 143' TERM
trap 'WDG_CLEAN_EXIT=1; log "received SIGINT, aborting action"; exit 130' INT
trap '[ "$WDG_CLEAN_EXIT" = "1" ] || log_error "watchdog EXITED unexpectedly (last_state=$(cat $STATE_FILE 2>/dev/null || echo ?))"' EXIT

get_iface() {
    sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null
}

# C084: 统一核验 run/cleanup_rules.marker (600s 抑制窗口, 过期或脏时间戳自动回收)
_CLEANUP_MARKER_AGE=0
cleanup_rules_marker_active() {
    local marker="$HNC_DIR/run/cleanup_rules.marker" mts now _age
    [ -f "$marker" ] || return 1
    mts=$(tr -d ' \t\r\n' < "$marker" 2>/dev/null)
    now=$(date +%s 2>/dev/null) || now=0
    case "$mts:$now" in
        *[!0-9:]*|:*)
            rm -f "$marker" 2>/dev/null
            return 1
            ;;
    esac
    if [ "$mts" -gt 0 ] && [ "$now" -gt 0 ]; then
        _age=$((now - mts))
        if [ "$_age" -ge -5 ] && [ "$_age" -lt 600 ]; then
            _CLEANUP_MARKER_AGE="$_age"
            return 0
        fi
    fi
    rm -f "$marker" 2>/dev/null
    return 1
}

# ── 完整恢复 ─────────────────────────────────────────────────
full_restore() {
    local reason=$1
    log "RESTORE triggered: $reason"
    local _frc="$HNC_DIR/run/watchdog_full_restore.count" _frn
    _frn=$(cat "$_frc" 2>/dev/null); case "$_frn" in *[!0-9]*|'') _frn=0 ;; esac
    echo $((_frn + 1)) > "$_frc" 2>/dev/null || true
    if cleanup_rules_marker_active; then
        log "RESTORE skipped: cleanup_rules marker active (${_CLEANUP_MARKER_AGE}s ago, suppress 600s)"
        return 0
    fi
    local iface=$(get_iface)
    if [ -z "$iface" ]; then
        log "RESTORE skipped: no valid iface"
        return 1
    fi

    if ! tc_repair_allowed; then
        return 0
    fi

    sh "$HNC_DIR/bin/iptables_manager.sh" init >> "$LOG" 2>&1
    sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$LOG" 2>&1 || true
    run_capability_probe_active "$iface"
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1 || true
        log "RESTORE tc skipped: tc_htb=false; iptables + blacklist restored only"
        return 0
    fi
    sh "$HNC_DIR/bin/tc_manager.sh" init "$iface" >> "$LOG" 2>&1
    local tc_init_rc=$?
    if [ $tc_init_rc -ne 0 ]; then
        log "full_restore: tc init rc=$tc_init_rc, continuing to restore anyway"
    fi
    # tc_manager.sh restore 内部末尾已执行 v6_sync.sh sync, 外层无需再重复跑第二遍
    sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
    local tc_restore_rc=$?
    if [ $tc_restore_rc -eq 12 ] || [ $tc_restore_rc -eq 11 ]; then
        echo "$(date +%s 2>/dev/null)" > "$RUN/tc_restore_pending" 2>/dev/null || true
    else
        rm -f "$RUN/tc_restore_pending" 2>/dev/null
        rm -f "$RUN/app_limits.full_state.sig" "$RUN/app_qos.sig" 2>/dev/null
        touch "$RUN/app_limit.dirty" 2>/dev/null || true
        [ -f "$HNC_DIR/bin/apply_app_limits.sh" ] && sh "$HNC_DIR/bin/apply_app_limits.sh" >> "$LOG" 2>&1 || true
        [ -f "$HNC_DIR/bin/apply_app_qos.sh" ] && sh "$HNC_DIR/bin/apply_app_qos.sh" >> "$LOG" 2>&1 || true
        if tr -d '\n' < "$HNC_DIR/data/rules.json" 2>/dev/null | grep -Eq '"client_isolation_enabled"[[:space:]]*:[[:space:]]*(true|"true")'; then
            sh "$HNC_DIR/bin/iptables_manager.sh" set_isolation "$iface" on >> "$LOG" 2>&1 || true
        fi
    fi
    if [ $tc_restore_rc -eq 12 ] || [ $tc_restore_rc -eq 11 ]; then
        log "full_restore: tc restore busy/lock lost (rc=$tc_restore_rc), not counted as repair failure; marked pending"
    elif [ $tc_init_rc -eq 0 ] && [ $tc_restore_rc -eq 0 ]; then
        tc_repair_record 1
    else
        tc_repair_record 0
    fi
    log "RESTORE complete init_rc=$tc_init_rc restore_rc=$tc_restore_rc"
}

# do_full_init: PENDING -> ACTIVE:<iface>
do_full_init() {
    local iface=$1 ip=$2
    if cleanup_rules_marker_active; then
        log "INIT skipped: cleanup_rules marker active (${_CLEANUP_MARKER_AGE}s ago, suppress 600s)"
        return 0
    fi
    log "STATE PENDING -> ACTIVE:$iface (ip=$ip), running first-time init"
    sh "$HNC_DIR/bin/iptables_manager.sh" init >> "$LOG" 2>&1
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$LOG" 2>&1 || true
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1 || true
        log "do_full_init: tc skipped because tc_htb=false; iptables + blacklist only"
    else
        sh "$HNC_DIR/bin/tc_manager.sh" init "$iface" >> "$LOG" 2>&1
        local tc_init_rc=$?
        if [ $tc_init_rc -ne 0 ]; then
            log "do_full_init: tc init rc=$tc_init_rc, continuing to restore"
        fi
        # tc_manager.sh restore 内部已同步 v6_sync.sh sync
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
    fi
    _pref=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface 2>/dev/null) || _pref=""
    _pref=$(printf '%s' "$_pref" | tr -d '[:space:]')
    case "$_pref" in \"*\") _pref=${_pref#\"}; _pref=${_pref%\"} ;; esac
    if [ -z "$_pref" ] || [ "$_pref" = "auto" ] || [ "$_pref" = "$iface" ]; then
        sh "$HNC_DIR/bin/json_set.sh" top hotspot_iface "$iface" >> "$LOG" 2>&1
    else
        log "skip hotspot_iface overwrite: user pref=$_pref, detected=$iface"
    fi
    echo "ACTIVE:$iface" > "$STATE_FILE"
    log "STATE entered ACTIVE:$iface"
    [ -f "$HNC_DIR/bin/hnc_offload_guard.sh" ] && sh "$HNC_DIR/bin/hnc_offload_guard.sh" apply >> "$LOG" 2>&1 || true

    # 补齐首次入 ACTIVE 时的单应用限速、应用感知 QoS 与 AP 客户端隔离恢复
    rm -f "$RUN/app_limits.full_state.sig" "$RUN/app_qos.sig" 2>/dev/null
    touch "$RUN/app_limit.dirty" 2>/dev/null || true
    if watchdog_tc_core_supported; then
        [ -f "$HNC_DIR/bin/apply_app_limits.sh" ] && sh "$HNC_DIR/bin/apply_app_limits.sh" >> "$LOG" 2>&1 || true
        [ -f "$HNC_DIR/bin/apply_app_qos.sh" ] && sh "$HNC_DIR/bin/apply_app_qos.sh" >> "$LOG" 2>&1 || true
    fi
    if tr -d '\n' < "$HNC_DIR/data/rules.json" 2>/dev/null | grep -Eq '"client_isolation_enabled"[[:space:]]*:[[:space:]]*(true|"true")'; then
        sh "$HNC_DIR/bin/iptables_manager.sh" set_isolation "$iface" on >> "$LOG" 2>&1 || true
    fi

    (
        sleep 15
        if cleanup_rules_marker_active; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WDG] delayed re-restore skipped: cleanup_rules marker active" >> "$LOG"
            exit 0
        fi
        cur_state=$(cat "$STATE_FILE" 2>/dev/null)
        case "$cur_state" in
            ACTIVE:*)
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WDG] delayed re-restore fired (+15s post-init) to refresh stale IPs" >> "$LOG"
                if watchdog_tc_core_supported; then
                    sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
                else
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WDG] delayed re-restore skipped: tc_htb=false" >> "$LOG"
                fi
                ;;
        esac
    ) </dev/null >/dev/null 2>&1 &
}

# do_migrate: ACTIVE:<old_iface> -> ACTIVE:<new_iface>
do_migrate() {
    local old=$1 new=$2 new_ip=$3
    log "STATE ACTIVE:$old -> ACTIVE:$new (ip=$new_ip), migrating"
    run_capability_probe_active "$new"
    if watchdog_tc_core_supported; then
        sh "$HNC_DIR/bin/tc_manager.sh" cleanup "$old" >> "$LOG" 2>&1
        sh "$HNC_DIR/bin/tc_manager.sh" init "$new" >> "$LOG" 2>&1
        local tc_init_rc=$?
        if [ $tc_init_rc -ne 0 ]; then
            log_error "do_migrate: tc init failed on $new (rc=$tc_init_rc), reverting to PENDING"
            echo "PENDING" > "$STATE_FILE"
            return $tc_init_rc
        fi
        # tc_manager.sh restore 内部已同步 v6_sync.sh sync
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
    else
        watchdog_mark_tc_unsupported_once tc_htb
        log "do_migrate: tc skipped because tc_htb=false"
    fi
    _pref=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface 2>/dev/null) || _pref=""
    _pref=$(printf '%s' "$_pref" | tr -d '[:space:]')
    case "$_pref" in \"*\") _pref=${_pref#\"}; _pref=${_pref%\"} ;; esac
    if [ -z "$_pref" ] || [ "$_pref" = "auto" ] || [ "$_pref" = "$new" ]; then
        sh "$HNC_DIR/bin/json_set.sh" top hotspot_iface "$new" >> "$LOG" 2>&1
    else
        log "skip hotspot_iface overwrite (migrate): user pref=$_pref, detected=$new"
    fi
    echo "ACTIVE:$new" > "$STATE_FILE"
    log "STATE entered ACTIVE:$new"
    [ -f "$HNC_DIR/bin/hnc_offload_guard.sh" ] && sh "$HNC_DIR/bin/hnc_offload_guard.sh" apply >> "$LOG" 2>&1 || true
    rm -f "$RUN/app_limits.full_state.sig" "$RUN/app_qos.sig" 2>/dev/null
    if [ -f "$RUN/app_qos.plan" ]; then
        sed "s/^iface .*/iface $new/" "$RUN/app_qos.plan" > "$RUN/app_qos.plan.mig" 2>/dev/null && mv -f "$RUN/app_qos.plan.mig" "$RUN/app_qos.plan" 2>/dev/null || true
    fi
    [ -f "$HNC_DIR/bin/apply_app_limits.sh" ] && sh "$HNC_DIR/bin/apply_app_limits.sh" >> "$LOG" 2>&1 || true
    [ -f "$HNC_DIR/bin/apply_app_qos.sh" ] && sh "$HNC_DIR/bin/apply_app_qos.sh" >> "$LOG" 2>&1 || true
    if tr -d '\n' < "$HNC_DIR/data/rules.json" 2>/dev/null | grep -Eq '"client_isolation_enabled"[[:space:]]*:[[:space:]]*(true|"true")'; then
        sh "$HNC_DIR/bin/iptables_manager.sh" set_isolation "$new" on >> "$LOG" 2>&1 || true
    fi
    sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true
}

# ─── 主动 uplink health check ─────────────────────────
ensure_tc_uplink_healthy() {
    local capv
    capv=$(watchdog_cap_uplink_value 2>/dev/null || echo unknown)
    if [ "$capv" = "false" ]; then
        watchdog_mark_uplink_unsupported_once
        rm -f "$RUN/uplink_fail_count" 2>/dev/null || true
        return 0
    fi

    local iface
    iface=$(get_iface)
    [ -z "$iface" ] && iface="wlan2"
    local marker="$RUN/uplink_unsupported"
    local fail_file="$RUN/uplink_fail_count"
    local threshold=8
    local cooldown=1800
    local now since
    now=$(date +%s 2>/dev/null || echo 0)
    if [ -f "$marker" ]; then
        since=$(sed -n 's/.*"since"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$marker" 2>/dev/null | head -1)
        if [ -n "$since" ] && [ $((now - since)) -lt $cooldown ]; then
            return 0
        fi
        log "ensure_tc_uplink: re-probing after degraded cooldown"
        rm -f "$marker" "$fail_file" 2>/dev/null || true
    fi

    local ok=1
    if ! ip link show ifb0 >/dev/null 2>&1; then
        ip link add ifb0 type ifb 2>/dev/null || true
    fi
    if ! ip link show ifb0 >/dev/null 2>&1; then
        ok=0
    else
        local _ifb_root
        _ifb_root=$(tc qdisc show dev ifb0 2>/dev/null | awk '$4 == "root" {print $2; exit}')
        if [ "$_ifb_root" != "htb" ]; then
            log "ensure_tc_uplink: ifb0 root='$_ifb_root' repairing"
            ip link set dev ifb0 up 2>/dev/null || true
            tc qdisc del dev ifb0 root 2>/dev/null || true
            tc qdisc add dev ifb0 root handle 1: htb default 9999 r2q 10 2>/dev/null || ok=0
            tc class add dev ifb0 parent 1:  classid 1:1    htb rate 1Gbit ceil 1Gbit burst 200k cburst 200k 2>/dev/null || true
            tc class add dev ifb0 parent 1:1 classid 1:9999 htb rate 1Gbit ceil 1Gbit burst 200k cburst 200k 2>/dev/null || true
            tc qdisc add dev ifb0 parent 1:9999 handle 9999: fq_codel 2>/dev/null || tc qdisc add dev ifb0 parent 1:9999 handle 9999: sfq perturb 10 2>/dev/null || true
        fi
    fi

    if ! tc filter show dev "$iface" ingress 2>/dev/null | grep -qiE "mirred.*ifb0" \
       && ! tc filter show dev "$iface" parent ffff: 2>/dev/null | grep -qiE "mirred.*ifb0"; then
        local retry_marker="$HNC_DIR/run/ensure_tc_uplink.last_retry"
        local last_retry=$(cat "$retry_marker" 2>/dev/null || echo 0)
        local since_last=$((now - last_retry))
        if [ "$since_last" -lt 300 ]; then
            :
        else
            log "ensure_tc_uplink: $iface ingress mirred missing, repairing via tc_manager"
            sh "$HNC_DIR/bin/tc_manager.sh" ensure_ingress "$iface" >> "$LOG" 2>&1 || ok=0
            echo "$now" > "$retry_marker" 2>/dev/null || true
            sleep 1
            if ! tc filter show dev "$iface" ingress 2>/dev/null | grep -qiE "mirred.*ifb0" \
               && ! tc filter show dev "$iface" parent ffff: 2>/dev/null | grep -qiE "mirred.*ifb0"; then
                log "ensure_tc_uplink: $iface ingress mirred STILL missing after repair (kernel rejects?)"
                ok=0
            else
                log "ensure_tc_uplink: $iface ingress mirred repair OK"
            fi
        fi
    fi

    if [ "$ok" = "0" ]; then
        local cnt
        cnt=$(cat "$fail_file" 2>/dev/null || echo 0)
        cnt=$((cnt + 1))
        echo "$cnt" > "$fail_file" 2>/dev/null || true
        if [ $cnt -ge $threshold ]; then
            log "ensure_tc_uplink: marking uplink_unsupported after $cnt failures"
            echo "{\"ifb_unsupported\":true,\"since\":$now,\"reason\":\"ifb0 or ingress mirred unrecoverable\"}" > "$marker" 2>/dev/null || true
        fi
    else
        rm -f "$fail_file" "$marker" 2>/dev/null || true
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# action mode — invoked by the Go hnc_watchdog binary to execute
# individual business actions WITHOUT entering any main loop.
#
# Contract:
#   sh watchdog.sh action <name> [args...]
#   exit code = action's return code (0 = ok, non-zero = failure; unknown = 64)
# ═══════════════════════════════════════════════════════════════════════════
if [ "${1:-}" = "action" ]; then
    WDG_CLEAN_EXIT=1
    shift
    _action="${1:-}"
    shift 2>/dev/null || true
    case "$_action" in
        full_restore)         full_restore "${1:-go_request}"  ; exit $? ;;
        full_init)            do_full_init "$1" "$2"           ; exit $? ;;
        migrate)              do_migrate "$1" "$2" "$3"        ; exit $? ;;
        cleanup_stale_rules)  cleanup_stale_rules_daily        ; exit $? ;;
        rotate_logs)          rotate_logs_periodic             ; exit $? ;;
        capability_probe)     run_capability_probe_active "$1" ; exit $? ;;
        tc_uplink_healthy)    ensure_tc_uplink_healthy         ; exit $? ;;
        prune_dup_hotspotd)   prune_duplicate_hotspotd         ; exit $? ;;
        *) echo "watchdog.sh action: unknown command '$_action'" >&2; exit 64 ;;
    esac
fi

WDG_CLEAN_EXIT=1
log "主循环已由 bin/hnc_watchdog 承担, watchdog.sh 只提供 action (invoked without action, exit 2)"
exit 2
