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
# v5.22 功耗: run/activity.json 读取器(纯内建); 缺失时退化为「永远活跃」= 旧行为
if [ -f "$HNC_DIR/bin/hnc_activity.sh" ]; then
    . "$HNC_DIR/bin/hnc_activity.sh"
elif [ -f "${0%/*}/hnc_activity.sh" ]; then
    . "${0%/*}/hnc_activity.sh"
fi
# v5.33: prune_duplicate_hotspotd(action prune_dup_hotspotd)与 service.sh 共用 bin/hnc_proc.sh
if [ -f "$HNC_DIR/bin/hnc_proc.sh" ]; then
    . "$HNC_DIR/bin/hnc_proc.sh"
elif [ -f "${0%/*}/hnc_proc.sh" ]; then
    . "${0%/*}/hnc_proc.sh"
fi
command -v hnc_act_load >/dev/null 2>&1 || {
    hnc_act_load() { ACT_OK=0; ACT_LEVEL=unknown; ACT_SCREEN_OFF=0; ACT_SCREEN_ON=0; ACT_HOTSPOT=1; ACT_CLIENTS=1; ACT_WEBUI=1; return 1; }
}
# rc30.13.1 cleanup: RULES_FILE 在此文件无引用. 真实读 rules.json 都是
# 通过 sh "$HNC_DIR/bin/json_set.sh" 子调用 (它自己拼路径). 删 SC2034 死变量.
LOG=$HNC_DIR/logs/watchdog.log
RUN=$HNC_DIR/run

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [WDG] $1" >> "$LOG" 2>/dev/null || true
}

# v4.0 Patch 1.6: [ERROR] 前缀便于 grep 故障排查
# log "foo" 普通事件 / log_error "foo" 真实错误 / log_info 已经被 log 占用就不另加
log_error() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [WDG] [ERROR] $1" >> "$LOG" 2>/dev/null || true
}

# hotfix16.5: capability-aware uplink gate. If capability_probe already proved
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

# hotfix17.3: rerun capability probe once hotspot iface is ACTIVE.
# Early service probe can run before hotspot exists and write unknown/false values.
# v5.27: Go 看门狗每轮(热点开着 60 秒)都调 action capability_probe, 旧的 30 秒节流等于
# 每分钟跑一次完整探测(建临时网卡 / ifb、逐个加 qdisc、qdisc_caps.sh、重写
# capabilities.json)—— 真机热点空转 1 小时 watchdog 约 530 CPU 秒。能力开机后不会变:
# 本次开机测过且同一网卡 6 小时内不重测; 网卡变了(热点重建成别的口)或刚开机立即重测。
# 标记文件格式 "<秒> <网卡>"; 旧格式只有秒数时视为同一网卡(兼容)。
CAP_PROBE_MIN_INTERVAL=21600
run_capability_probe_active() {
    local iface="$1" now last last_if
    [ -n "$iface" ] || return 0
    [ -x "$HNC_DIR/bin/capability_probe.sh" ] || return 0
    ip link show "$iface" >/dev/null 2>&1 || return 0

    now=$(date +%s 2>/dev/null || echo 0)
    read -r last last_if 2>/dev/null < "$RUN/capability_probe_last"
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    [ -n "$last_if" ] || last_if="$iface"
    # 本次开机还没测过(标记早于开机时刻)→ 必须测: run/ 跨重启保留, 开机早期那次探测
    # 可能在热点出现前做的(hotfix17.3 的原因)。
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
    log "hotfix17.3: running capability_probe for active iface=$iface"
    HNC="$HNC_DIR" sh "$HNC_DIR/bin/capability_probe.sh" >> "$HNC_DIR/logs/capabilities.log" 2>&1 || \
        log "hotfix17.3: capability_probe failed for iface=$iface"
}

# hotfix17.7: TC repair circuit breaker.
# If tc init/restore keeps failing, stop automatic repairs for a while to avoid
# UI stalls, battery drain, and watchdog log storms. Manual WebUI operations still
# call tc_manager directly and can recover the state.
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

# v4.0 Patch 1.6 轮转的最后时间(rotate_logs action 用; 心跳已随 shell 主循环移入 Go 版)
LAST_LOG_ROTATE=0
LAST_STALE_CLEANUP_DAY=""   # hotfix10: 每天跑一次 stale rules cleanup
LOG_ROTATE_INTERVAL=300   # 5 分钟看一次(粒度足够,开销低)

rotate_logs_periodic() {
    local now; now=$(date +%s)
    if [ $((now - LAST_LOG_ROTATE)) -ge $LOG_ROTATE_INTERVAL ]; then
        sh "$HNC_DIR/bin/log_rotate.sh" check 2>/dev/null || true
        LAST_LOG_ROTATE=$now
    fi
}

cleanup_stale_rules_daily() {
    local day
    day=$(date +%Y%m%d 2>/dev/null) || day=unknown
    # hotfix11: 不在 PENDING/热点未就绪时跑清理,避免开机早期 devices.json 还没稳定就删规则。
    case "$(cat "$STATE_FILE" 2>/dev/null || echo PENDING)" in
        ACTIVE:*) ;;
        *) return 0 ;;
    esac
    [ "$day" = "$LAST_STALE_CLEANUP_DAY" ] && return 0
    LAST_STALE_CLEANUP_DAY="$day"
    [ -x "$HNC_DIR/bin/cleanup_stale_rules.sh" ] || return 0
    sh "$HNC_DIR/bin/cleanup_stale_rules.sh" >> "$HNC_DIR/logs/cleanup_stale.log" 2>&1 &
    log "stale rules cleanup scheduled for day=$day"
}
# v4.0 Patch 1.6 意外退出 trap: watchdog 不应该正常退出,退出就是 bug
# TERM/INT 是模块关闭(正常),设 flag 让 EXIT trap 知道是正常退出
WDG_CLEAN_EXIT=0
trap 'WDG_CLEAN_EXIT=1; log "received signal, shutting down"; exit 0' TERM INT
trap '[ "$WDG_CLEAN_EXIT" = "1" ] || log_error "watchdog EXITED unexpectedly (last_state=$(cat $STATE_FILE 2>/dev/null || echo ?))"' EXIT

# 当前热点网卡(full_restore / ensure_tc_uplink_healthy 用)。每个 action 都是
# 新进程, v3.4.1 起的进程内 5 分钟缓存从没命中过, v5.33 删; 防抖由
# hnc_iface.sh 的 run/iface_detect.json(TTL + 候选签名)负责。
get_iface() {
    sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null
}

# ── 完整恢复 ─────────────────────────────────────────────────
full_restore() {
    local reason=$1
    log "RESTORE triggered: $reason"
    # rc42: 持久累计 full_restore 次数,供 /api/sla 面板(tc 树被重建几次是关键健康信号)。
    local _frc="$HNC_DIR/run/watchdog_full_restore.count" _frn
    _frn=$(cat "$_frc" 2>/dev/null); case "$_frn" in *[!0-9]*|'') _frn=0 ;; esac
    echo $((_frn + 1)) > "$_frc" 2>/dev/null || true
    # rc3.1.13.2 修 P1 (review §2): cleanup rules mode 后用户通常正在重配,
    # 600s 内 skip restore. 之前 watchdog 60s 内就把规则全恢复, 用户白清.
    local marker="$HNC_DIR/run/cleanup_rules.marker"
    if [ -f "$marker" ]; then
        local mts; mts=$(cat "$marker" 2>/dev/null)
        local now; now=$(date +%s 2>/dev/null) || now=0
        if [ -n "$mts" ] && [ -n "$now" ] && [ $((now - mts)) -lt 600 ]; then
            log "RESTORE skipped: cleanup_rules marker active ($((now - mts))s ago, suppress 600s)"
            return 0
        fi
        # marker 过期, 删掉
        rm -f "$marker" 2>/dev/null
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
    # v5.11: 白名单模式落到 iptables(init 后链可能是空的; 热点接口变化时 DROP 的 -i 也要跟着换)
    sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true  # v5.21: 加密 DNS 策略
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$LOG" 2>&1 || true  # v5.22: WebUI 访问白名单自愈(与接口无关, 幂等)
    run_capability_probe_active "$iface"
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        # v5.12: 上面 iptables init 已 flush HNC_CTRL,黑名单只在 tc_manager restore
        # 里恢复。旧代码 tc_htb=false 时直接 return → 黑名单设备恢复上网。restore
        # 自身按能力跳过所有 tc 操作(limit/delay/uplink 均有 capability 门控),
        # 只做黑名单与 mark 恢复,可以安全调用。
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1 || true
        log "RESTORE tc skipped: tc_htb=false; iptables + blacklist restored only"
        return 0
    fi
    sh "$HNC_DIR/bin/tc_manager.sh" init "$iface" >> "$LOG" 2>&1
    local tc_init_rc=$?
    # rc3.1.33 修 #1: 跟 do_full_init 对称, tc init 失败时不跑 restore + 不刷
    # _HEALTH_TS, 让下轮 health check 重新触发完整 RESTORE 路径. 之前会写
    # "RESTORE complete" 但实际半装配, _HEALTH_TS=0 强制下轮再 restore →
    # 死循环刷 RESTORE 占满 watchdog.log + 永远恢复不了.
    #
    # v5.0 alpha.4 hotfix1: 修改策略 — init_tc 失败时继续跑 restore
    # 真机发现 init_tc 有时装 install_ingress_mirred 失败 (ColorOS tc 冷启动竞态)
    # 导致 init_tc rc != 0, skip restore. 但 restore_rules 开头有幂等的
    # install_ingress_mirred 强制调用 (hotfix2), 反而是补救的机会. skip 掉就永远没机会装
    # 上 ingress matchall filter, 上行限速永远失效 (Ling 真机 alpha.3/4 反复验证).
    #
    # 新策略: init_tc 失败只记 WARNING, 继续跑 restore. restore 内部会再次
    # 尝试 install_ingress_mirred. 若 restore 自己也整体失败, 下轮 health check
    # 会再次触发完整 RESTORE (原 _HEALTH_TS=0 机制保留)
    if [ $tc_init_rc -ne 0 ]; then
        log "full_restore: tc init rc=$tc_init_rc, continuing to restore anyway (hotfix1 fallback)"
    fi
    sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
    local tc_restore_rc=$?
    # v5.9.1: rc=12 是 tc_manager 的 busy 约定(拿不到 tc_action_lock,或
    # restore 中途发现锁已易主而主动中止)。这是良性竞争 —— 说明另一个进程
    # 正在正常改 tc 树,不是修复失败。计进 tc_repair 熔断器会让 3 次竞争就
    # 停掉 5 分钟的自动修复能力(语义错配)。只置 _HEALTH_RC=1 让下轮重试。
    # v5.12: 上面 iptables init 已把 HNC_MARK / HNC_CTRL(黑名单)整链 flush,只有
    # restore 才会把 mark 和黑名单加回来。restore 因锁竞争退 12(tc_action_lock)或
    # 11(gate_lock 超时)时,旧代码"置 _HEALTH_RC=1 让下轮重试"并不成立:紧接着
    # _HEALTH_TS=0 让缓存失效,Go 版每轮又是新进程 —— 下轮 check_health 看到链都在
    # 就判健康,黑名单设备从此恢复上网、v6 限速失去 mark,直到下次别的原因触发恢复。
    # 落一个 pending 标记,Go 看门狗的规则健康检查(native.go)见标记即判不健康,
    # 由(已限流的)下轮再恢复。
    if [ $tc_restore_rc -eq 12 ] || [ $tc_restore_rc -eq 11 ]; then
        echo "$(date +%s 2>/dev/null)" > "$RUN/tc_restore_pending" 2>/dev/null || true
    else
        rm -f "$RUN/tc_restore_pending" 2>/dev/null
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

# ── Doze 检测 ────────────────────────────────────────────────
is_doze() {
    # v5.22: httpd 探到亮屏就不可能在 Doze —— 省掉每轮 cmd power + dumpsys battery
    # 两次 binder 调用(PENDING 态每 10 秒一轮, 这是热点关着时 watchdog 最大的开销之一)。
    # 判新鲜度要多 fork 一次 date, 这里不判: 文件过期(httpd 挂了)时最多是亮屏时
    # 漏掉「电量 <5% 降频」, 不影响规则正确性。
    if hnc_act_load && [ "$ACT_SCREEN_ON" = 1 ]; then
        return 1
    fi
    cmd power get-idle-mode 2>/dev/null | grep -qiE "^(deep|light)$" && return 0
    local lvl
    lvl=$(dumpsys battery 2>/dev/null | awk '/^[[:space:]]*level:/{print $2; exit}')
    [ -n "$lvl" ] && [ "$lvl" -lt 5 ] 2>/dev/null && return 0
    return 1
}

# ═══ v4.0.0-patch1.5 Defer Init 状态机 ══════════════════════════════
# 见设计文档(Gemini 确认的方案):
#   PENDING   → 还没探到有效热点,什么都不做
#   ACTIVE:X  → 已在 iface X 上挂了规则 + httpd 跑着
#   迁移      → X 消失 or 变成 Y 时 cleanup X + init Y
#
# 状态保存在 $RUN/hnc_state,值是 "PENDING" 或 "ACTIVE:<iface>"。
# 重启 watchdog 时读这个文件恢复状态(避免重启就重挂规则)。

STATE_FILE="$RUN/hnc_state"

# do_full_init: PENDING → ACTIVE:<iface>
# 场景: 从来没 init 过(开机) or 刚刚热点重开。
# 做: iptables init + tc init on iface + tc restore + v6 sync + 必要时拉 httpd
# rc3.1.32: tc init 如果失败 (root htb add 冷启时序 bug 重试 3 次仍失败),
# 不推进 STATE 到 ACTIVE, 保持 PENDING 让下一轮 probe 重新触发 do_full_init.
# 典型场景: watchdog 启动过早撞上 wlan2 kernel 切换, 再等 1 轮 (60s) 通常就能成功.
do_full_init() {
    local iface=$1 ip=$2
    log "STATE PENDING -> ACTIVE:$iface (ip=$ip), running first-time init"
    sh "$HNC_DIR/bin/iptables_manager.sh" init >> "$LOG" 2>&1
    # v5.11: 白名单模式落到 iptables(init 后链可能是空的; 热点接口变化时 DROP 的 -i 也要跟着换)
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    HNC_WL_IFACE="$iface" sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true  # v5.21
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$LOG" 2>&1 || true  # v5.22: WebUI 访问白名单自愈(与接口无关, 幂等)
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        # v5.12: 同 full_restore —— 黑名单只在 restore 里恢复,tc_htb=false 也要跑
        # (restore 内部按能力跳过 tc),否则开机/开热点后黑名单永远不生效。
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1 || true
        log "do_full_init: tc skipped because tc_htb=false; iptables + blacklist only"
    else
        sh "$HNC_DIR/bin/tc_manager.sh" init "$iface" >> "$LOG" 2>&1
        local tc_init_rc=$?
        # v5.0 alpha.4 hotfix1: 跟 full_restore 一致策略
        # tc init 里 install_ingress_mirred 失败 (ColorOS tc 冷启动 FAILED) 会让
        # init_tc rc != 0, 原逻辑 return 跳过 restore, 导致 restore 内部的 hotfix2
        # 幂等 install_ingress_mirred 永远没机会跑, 上行限速永远失效。
        # 新策略: 记 WARN 继续 restore, restore 里会重新尝试
        if [ $tc_init_rc -ne 0 ]; then
            log "do_full_init: tc init rc=$tc_init_rc, continuing to restore (hotfix1 fallback)"
        fi
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
        sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1
    fi
    # 写 rules.json.hotspot_iface,给 WebUI 显示。
    # v5.9.92: 用户设置了非 auto 偏好时不覆写 —— 否则"接口暂时消失"的
    # 瞬间(重启/切换中)探测值会把用户刚保存的偏好冲掉。偏好与探测一致
    # 时写同值无感; 不一致时尊重偏好(device_detect 探测已读偏好, 探测
    # 结果 ≠ 偏好仅发生在偏好接口暂时不存在的窗口)。
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

    # rc3.1.31 Bug B gap 修复 · 冷启动 do_full_init 可能跑在客户端连上热点前,
    # 此时 devices.json 是空的 → restore_rules 拿不到 live IP 走了 rules.json 的
    # stale fallback → tc u32 filter 装到了旧 IP → Mi-10 新 IP 流量不 match.
    # 15s 后再跑一次 restore, 给设备发现写者(v5.33 起只有 Go 看门狗)写 devices.json 的时间, get_current_ip
    # 能拿到真实 IP. restore_rules 幂等 (prio=100+mark_id 每 MAC 唯一, del-before-add,
    # IP 无变化则 no-op 只重复建 filter ~<50ms).
    # subshell 独立, 即便 watchdog 退出也自然降级 (STATE 被 reset 则 case 不匹配).
    (
        sleep 15
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
    # v5.12: ↑ 必须断开 stdio。Go hnc_watchdog 以 `watchdog.sh action full_init`
    # 调用本函数并用 cmd.Output() 收 stdout:后台子 shell 继承了那根管道,Output()
    # 要等它 sleep 15 + 整轮 restore 结束才返回;超过 actionTimeout(30s)即判
    # rc=-1 → "full_init returned rc=-1; staying PENDING" → 下一轮重跑整套 init。
    # 子 shell 内部的日志本来就显式 >> "$LOG",断开 stdio 不丢输出。
}

# do_migrate: ACTIVE:<old_iface> → ACTIVE:<new_iface>
# 场景: 热点接口换了(WiFi 热点 → USB tethering 等)
# 做: cleanup 旧 + init 新 + 杀 httpd 等下轮重拉绑新 IP
do_migrate() {
    local old=$1 new=$2 new_ip=$3
    log "STATE ACTIVE:$old -> ACTIVE:$new (ip=$new_ip), migrating"
    run_capability_probe_active "$new"
    if watchdog_tc_core_supported; then
        sh "$HNC_DIR/bin/tc_manager.sh" cleanup "$old" >> "$LOG" 2>&1
        sh "$HNC_DIR/bin/tc_manager.sh" init "$new" >> "$LOG" 2>&1
        local tc_init_rc=$?
        # rc3.1.33 修 #1: 跟 do_full_init 对称, tc init 失败时回退到 PENDING.
        # 之前继续写 ACTIVE:$new 但 tc 实际没装, watchdog 永远不会重 init →
        # 伪 ACTIVE 状态卡死.
        if [ $tc_init_rc -ne 0 ]; then
            log_error "do_migrate: tc init failed on $new (rc=$tc_init_rc), reverting to PENDING"
            echo "PENDING" > "$STATE_FILE"
            return $tc_init_rc
        fi
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
        sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1
    else
        watchdog_mark_tc_unsupported_once tc_htb
        log "do_migrate: tc skipped because tc_htb=false"
    fi
    # v5.9.92: 同 do_full_init —— 尊重用户偏好, 不无条件覆写
    _pref=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface 2>/dev/null) || _pref=""
    _pref=$(printf '%s' "$_pref" | tr -d '[:space:]')
    case "$_pref" in \"*\") _pref=${_pref#\"}; _pref=${_pref%\"} ;; esac
    if [ -z "$_pref" ] || [ "$_pref" = "auto" ] || [ "$_pref" = "$new" ]; then
        sh "$HNC_DIR/bin/json_set.sh" top hotspot_iface "$new" >> "$LOG" 2>&1
    else
        log "skip hotspot_iface overwrite (migrate): user pref=$_pref, detected=$new"
    fi
    # v5.33: 不再为「拿新 IP 重绑」杀 httpd —— 远程端口监听 0.0.0.0, 网卡 / IP 变化
    # 无需重绑(v5.3.0-rc8 起就是 0.0.0.0, 这里一直白杀; 而且看门狗重拉 httpd 时
    # v5.32 及以前不带远程参数, 一迁移远程访问就没了)。
    echo "ACTIVE:$new" > "$STATE_FILE"
    log "STATE entered ACTIVE:$new"
    # v5.12: 白名单模式的 DROP 规则带 `-i <热点口>`(接口取自 hnc_state)。迁移后
    # 不重同步,DROP 仍挂在旧接口上,新接口上的非白名单设备全部放行(封锁失效)。
    # 必须在上面写入新 STATE 之后调用,whitelist_mode_on 才能拿到新接口。
    sh "$HNC_DIR/bin/whitelist_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/quic_block_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/connblock_sync.sh" >> "$LOG" 2>&1 || true
    sh "$HNC_DIR/bin/encdns_sync.sh" >> "$LOG" 2>&1 || true  # v5.21: 加密 DNS 策略
}

# ─── v5.1 RC1 主动 uplink health check ─────────────────────────
# 每 60s 轮询一次, 不触发 full_restore, 直接 inline 修复
ensure_tc_uplink_healthy() {
    # hotfix16.4/16.5: IFB/mirred unsupported is a degraded uplink state, not a fatal health failure.
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
        since=$(sed -n 's/.*"since"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$marker" 2>/dev/null | head -n1)
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
        # rc30.8: 加修复尝试冷却. 如果上次尝试还没满 5 分钟, skip (避免日志刷屏 +
        # 避免 CPU 浪费). 用户日志显示这条每分钟都触发, 修了又掉, 大概率是
        # ColorOS 16 内核拒绝 ingress mirred. 与其每分钟重试, 不如冷却.
        local retry_marker="$HNC_DIR/run/ensure_tc_uplink.last_retry"
        local last_retry=$(cat "$retry_marker" 2>/dev/null || echo 0)
        local since_last=$((now - last_retry))
        if [ "$since_last" -lt 300 ]; then
            # 静默 skip. 不写日志.
            :
        else
            log "ensure_tc_uplink: $iface ingress mirred missing, repairing via tc_manager"
            sh "$HNC_DIR/bin/tc_manager.sh" ensure_ingress "$iface" >> "$LOG" 2>&1 || ok=0
            echo "$now" > "$retry_marker" 2>/dev/null || true
            # 修复后立即验证. 如果还是 missing, 立即标记 ok=0 让 fail_count 上去
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
# rc30.1: action mode — invoked by the Go hnc_watchdog binary to execute
# individual business actions WITHOUT entering any main loop. v5.26: the
# legacy shell main loop has been removed — running this script without an
# `action` argument now logs and exits 2. There is no shell fallback; the Go
# binary is the only main loop.
#
# Contract:
#   sh watchdog.sh action <name> [args...]
#   exit code = action's return code (0 = ok, non-zero = failure)
#   stdout = action's output (none of the remaining actions is parsed)
#
# v5.33: probe_hotspot / check_health / httpd_drift / get_iface were removed —
# the checks live only in Go (native.go); unknown names exit 64.
#
# Must be placed AFTER all function definitions.
# ═══════════════════════════════════════════════════════════════════════════
if [ "${1:-}" = "action" ]; then
    # v5.5.0-rc5 fix: action 子进程的退出是设计上的正常退出, 不是主循环异常崩溃.
    # 上面 ~line 238 的 EXIT trap 是为了捕获 mainLoop 异常退出报警, 但每次 Go
    # runAction 都 fork 这个脚本以 action 模式跑, 子进程跑到 case 里 exit $?
    # 干净退出时 trap 误以为是主循环崩了, 打 "watchdog EXITED unexpectedly".
    # PENDING 状态下每 10s tick 跑 probe_hotspot + prune_dup_hotspotd + 偶尔
    # is_doze, 平均 2-3 个 action subprocess / 10s, 节奏跟日志刷屏完美吻合.
    # 设这个 flag 让 EXIT trap 在 action 模式下变成 noop, 原本主循环监控完整保留.
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
        is_doze)              is_doze                          ; exit $? ;;
        prune_dup_hotspotd)   prune_duplicate_hotspotd         ; exit $? ;;
        *) echo "watchdog.sh action: unknown command '$_action'" >&2; exit 64 ;;
    esac
fi

# ── v5.26 T1: 主循环已删除 ─────────────────────────────────────
# 主循环由 Go 版 bin/hnc_watchdog(rc30.1+)承担; 本脚本只提供 action 业务动作。
# 不带 action 参数直接运行(旧 service.sh 的 shell 兜底路径)在此明确拒绝。
WDG_CLEAN_EXIT=1
log "主循环已由 bin/hnc_watchdog 承担, watchdog.sh 只提供 action (invoked without action, exit 2)"
exit 2
