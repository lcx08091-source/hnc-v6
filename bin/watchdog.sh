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
# 功耗优化：
#  1. 周期检查：60s 一次（Doze 时 180s）
#  2. 健康检查缓存 5s，避免重复 iptables 调用
#  3. Doze 模式暂停主动检查

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_constants.sh" ]; then
    . "$HNC_DIR/bin/hnc_constants.sh"
fi
HNC_HTTPS_PORT=${HNC_HTTPS_PORT:-8443}
HNC_LOOPBACK_PORT=${HNC_LOOPBACK_PORT:-8444}
HNC_HTTP_REDIR_PORT=${HNC_HTTP_REDIR_PORT:-8080}
# rc30.13.1 cleanup: RULES_FILE 在此文件无引用. 真实读 rules.json 都是
# 通过 sh "$HNC_DIR/bin/json_set.sh" 子调用 (它自己拼路径). 删 SC2034 死变量.
LOG=$HNC_DIR/logs/watchdog.log
RUN=$HNC_DIR/run

INTERVAL_NORMAL=60     # 规则正常时检查间隔
INTERVAL_RECOVERY=30   # v3.4.1：恢复后加密检查间隔（旧值 10s 太激进）
INTERVAL_DOZE=180      # Doze 模式

log() {
    [ -d "$(dirname "$LOG")" ] || mkdir -p "$(dirname "$LOG")" 2>/dev/null
    echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [WDG] $1" >> "$LOG" 2>/dev/null || true
}

# rc17: keep hotspotd single-instance during watchdog self-heal.  Keep the
# pidfile target when alive; otherwise repair pidfile to the first live process.
prune_duplicate_hotspotd() {
    local keep p seen
    keep=$(cat "$RUN/hotspotd.pid" 2>/dev/null)
    if [ -z "$keep" ] || ! kill -0 "$keep" 2>/dev/null; then
        keep=$(pidof hotspotd 2>/dev/null | awk '{print $1}')
        [ -n "$keep" ] && echo "$keep" > "$RUN/hotspotd.pid" 2>/dev/null || true
    fi
    seen=0
    for p in $(pidof hotspotd 2>/dev/null); do
        [ -z "$p" ] && continue
        if [ "$p" = "$keep" ] && [ "$seen" -eq 0 ]; then
            seen=1
            continue
        fi
        log "rc17: killing duplicate hotspotd pid=$p keep=$keep"
        kill -9 "$p" 2>/dev/null || true
    done
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
CAP_PROBE_MIN_INTERVAL=30
run_capability_probe_active() {
    local iface="$1" now last
    [ -n "$iface" ] || return 0
    [ -x "$HNC_DIR/bin/capability_probe.sh" ] || return 0
    ip link show "$iface" >/dev/null 2>&1 || return 0

    now=$(date +%s 2>/dev/null || echo 0)
    last=$(cat "$RUN/capability_probe_last" 2>/dev/null || echo 0)
    if [ $((now - last)) -lt "$CAP_PROBE_MIN_INTERVAL" ] 2>/dev/null; then
        return 0
    fi

    echo "$iface" > "$RUN/iface.cache" 2>/dev/null || true
    echo "$now" > "$RUN/capability_probe_last" 2>/dev/null || true
    log "hotfix17.3: running capability_probe for active iface=$iface"
    HNC="$HNC_DIR" sh "$HNC_DIR/bin/capability_probe.sh" >> "$HNC_DIR/logs/capabilities.log" 2>&1 || \
        log "hotfix17.3: capability_probe failed for iface=$iface"
    _HEALTH_TS=0
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


# v4.0 Patch 1.6 心跳 + 轮转的最后时间
# 每 5 分钟至少打一行 "alive" log(即使啥都没发生也有证据 watchdog 活着)
# 每次主循环也顺便调用一次 log_rotate,防止任何 log 涨爆
LAST_HEARTBEAT=0
LAST_LOG_ROTATE=0
LAST_STALE_CLEANUP_DAY=""   # hotfix10: 每天跑一次 stale rules cleanup
HEARTBEAT_INTERVAL=300    # 5 分钟
LOG_ROTATE_INTERVAL=300   # 5 分钟看一次(粒度足够,开销低)

heartbeat() {
    local now; now=$(date +%s)
    if [ $((now - LAST_HEARTBEAT)) -ge $HEARTBEAT_INTERVAL ]; then
        local state; state=$(cat "$STATE_FILE" 2>/dev/null || echo "?")
        local httpd="down"
        if [ -s "$RUN/httpd.pid" ] && kill -0 "$(cat "$RUN/httpd.pid")" 2>/dev/null; then
            httpd="ok"
        fi
        log "alive state=$state httpd=$httpd"
        LAST_HEARTBEAT=$now
    fi
}

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

# v3.4.1：iface 缓存。device_detect.sh iface 在 wlan0/wlan2 之间反复
# 横跳是 v3.4.0 watchdog 误触发 restore 的主要诱因。这里加 5 分钟缓存
# 完全屏蔽抖动。
IFACE_CACHE_TS=0
IFACE_CACHE_VAL=""
get_iface() {
    local now; now=$(date +%s)
    if [ -n "$IFACE_CACHE_VAL" ] && [ "$IFACE_CACHE_VAL" != "wlan0" ] \
       && [ $((now - IFACE_CACHE_TS)) -lt 300 ]; then
        echo "$IFACE_CACHE_VAL"
        return
    fi
    local v; v=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    # 只缓存有效结果（非空 + 非 wlan0）
    if [ -n "$v" ] && [ "$v" != "wlan0" ]; then
        IFACE_CACHE_VAL="$v"
        IFACE_CACHE_TS=$now
    fi
    echo "$v"
}

# ── 轻量健康检查（缓存 5s 结果）────────────────────────────
_HEALTH_TS=0
_HEALTH_RC=0
check_health() {
    local now=$(date +%s)
    [ $((now - _HEALTH_TS)) -lt 5 ] && return $_HEALTH_RC

    local rc=0
    local iface=$(get_iface)

    # 0. iface 必须有效
    [ -z "$iface" ] && rc=1

    # 1. TC 根 qdisc 是否为 HTB
    # 注意: 不同 iproute2 版本输出词序不同:
    #   老版: qdisc htb 1: dev wlan2 root refcnt ...   (root 在后)
    #   新版: qdisc htb 1: root refcnt ...              (root 在前, Android 16 / ColorOS)
    # 不要用 "root.*htb" 这样的有序正则,会导致新版永远匹配失败进 full_restore 死循环。
    # 要求: 某一行同时包含 "htb" 和 "root"(不限词序)
    # v4.0.0-patch1.3: 区分"命令失败"和"内容缺失":
    #   tc qdisc show 正常情况下永远 rc=0(即使 iface 不存在也返回空 + rc=0)
    #   所以这里只看内容。命令本身失败场景极少,不特殊处理
    if [ $rc -eq 0 ]; then
        if watchdog_tc_core_supported; then
            tc qdisc show dev "$iface" 2>/dev/null | grep "htb" | grep -q "root" || rc=1
        else
            watchdog_mark_tc_unsupported_once tc_htb
        fi
    fi

    # 2+3. iptables 链检查
    # v4.0.0-patch1.3 重要:
    #   a) 加 -w 2 等 xtables 锁(最多 2s),避免并发占锁时静默失败返回空
    #   b) 区分"命令失败(rc>=2)"和"规则缺失(命令 rc=0 但内容缺)":
    #      - iptables rc=2 = bad parameter (链不存在等"真丢失")
    #      - iptables rc=4 = resource problem (锁抢不到等临时故障)
    #      - iptables rc=0 + grep rc=1 = 规则真丢了
    #      只有 "真丢失" 才应该触发 RESTORE;临时故障 return 2 让主循环 skip 本轮
    #   c) HNC_MARK 链空是合法状态(用户没限速时),用 -S | rc 判断链存在性,
    #      不看链内规则数量

    # 2. HNC_MARK 链存在性
    if [ $rc -eq 0 ]; then
        iptables -w 2 -t mangle -S HNC_MARK >/dev/null 2>&1
        local ipt_rc=$?
        if [ $ipt_rc -eq 2 ]; then
            rc=1  # 链真丢了
        elif [ $ipt_rc -ne 0 ]; then
            # 锁抢不到等临时故障,不 RESTORE,跳过本轮
            _HEALTH_TS=$now
            _HEALTH_RC=2
            return 2
        fi
    fi

    # 3. HNC_RESTORE 链必须有 CONNMARK 规则(这个链不允许空,空了就是丢失)
    if [ $rc -eq 0 ]; then
        local restore_dump
        restore_dump=$(iptables -w 2 -t mangle -S HNC_RESTORE 2>/dev/null)
        local ipt_rc=$?
        if [ $ipt_rc -eq 2 ]; then
            rc=1  # 链真丢了
        elif [ $ipt_rc -ne 0 ]; then
            # 临时故障,跳过本轮
            _HEALTH_TS=$now
            _HEALTH_RC=2
            return 2
        else
            echo "$restore_dump" | grep -q 'CONNMARK' || rc=1
        fi
    fi

    _HEALTH_TS=$now
    _HEALTH_RC=$rc
    return $rc
}

# ── 完整恢复 ─────────────────────────────────────────────────
full_restore() {
    local reason=$1
    log "RESTORE triggered: $reason"
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
        _HEALTH_TS=0
        _HEALTH_RC=0
        return 0
    fi

    sh "$HNC_DIR/bin/iptables_manager.sh" init >> "$LOG" 2>&1
    run_capability_probe_active "$iface"
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        _HEALTH_TS=0
        _HEALTH_RC=0
        log "RESTORE tc skipped: tc_htb=false; iptables restored only"
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
    if [ $tc_init_rc -eq 0 ] && [ $tc_restore_rc -eq 0 ]; then
        tc_repair_record 1
        _HEALTH_RC=0
    else
        tc_repair_record 0
        _HEALTH_RC=1
    fi
    _HEALTH_TS=0
    log "RESTORE complete init_rc=$tc_init_rc restore_rc=$tc_restore_rc"
}

# ── 子服务存活检查 ──────────────────────────────────────────
# v3.5.0 P2-4: 防重启风暴 — 60 秒内同一服务最多重启 1 次
# 之前如果 hotspotd 启动后立刻 crash,会被无限重启,日志疯涨
# v3.5.0 P1-2:hotspotd 启动参数从 --daemon 改成 -d(hotspotd 实际只识别 -d)
HOTSPOTD_LAST_RESTART=0
DETECT_LAST_RESTART=0
RESTART_COOLDOWN=60  # 秒

# rc2 修 S6: spawn_lock 陈旧检测.
# 原代码 mkdir 失败直接 skip 本轮, 没有 stale detection — watchdog 上一次
# 被 SIGKILL (OOM/用户 pkill) 时若正持锁, 目录遗留, 新 watchdog 永远拿不到锁,
# 所有 daemon 重启动作被永久阻塞. 这里以 mtime 做 60 秒陈旧阈值: 超过就强释放.
# 返回 0 = 拿到锁, 1 = 被正当持有(他方活跃, skip 本轮).
SPAWN_LOCK_STALE_SEC=60
try_spawn_lock() {
    local lockdir=$1
    if mkdir "$lockdir" 2>/dev/null; then
        return 0
    fi
    local age
    age=$(( $(date +%s) - $(stat -c %Y "$lockdir" 2>/dev/null || echo 0) ))
    if [ "$age" -gt "$SPAWN_LOCK_STALE_SEC" ]; then
        log "WARN: spawn lock $lockdir stale (${age}s > ${SPAWN_LOCK_STALE_SEC}s), forcibly releasing"
        rmdir "$lockdir" 2>/dev/null
        mkdir "$lockdir" 2>/dev/null && return 0
    fi
    return 1
}

# ── v5.3.0-rc12 hnc_dpid 守护 (新增) ─────────────────────────
# dpid 自带 crash_loop 检测 (60s 内 3 次崩 = 进 crash_loop 模式), 所以
# 这里只做"PID 文件失效"重拉, 不做激进重启. crash_loop 模式下 daemon
# 自己 idle 不退出, PID 仍活, 这里不会误重拉.
#
# 不像 hotspotd, dpid 是纯观察 daemon, 死了不影响限速/网络功能,
# 用户也不会立刻察觉. 所以重启策略很保守: 仅在 PID 文件不存在或
# 进程死了的情况下尝试一次重拉, 失败不重试.
DPID_LAST_RESTART=0
ensure_dpid_running() {
    local dpid_bin="$HNC_DIR/bin/hnc_dpid"
    local dpid_guard="$HNC_DIR/bin/hnc_dpid_guard.sh"
    # rc30.0: Go supervisor preferred over shell guard.
    local dpid_supervisor="$HNC_DIR/bin/hnc_dpid_supervisor"
    local dpid_launcher="$dpid_bin"
    local dpid_pid_file="$RUN/dpid.pid"
    local dpid_guard_pid_file="$RUN/dpid_guard.pid"
    local watch_pid_file="$dpid_pid_file"

    [ ! -x "$dpid_bin" ] && return 0   # binary 不存在, 视为禁用了 DPI
    if [ -x "$dpid_supervisor" ]; then
        dpid_launcher="$dpid_supervisor"
        watch_pid_file="$dpid_guard_pid_file"
    elif [ -x "$dpid_guard" ]; then
        dpid_launcher="$dpid_guard"
        watch_pid_file="$dpid_guard_pid_file"
    fi

    # 进程还活就 OK. supervisor/guard 场景只看 dpid_guard.pid, 避免 dpid.pid child 退出导致重复拉.
    if [ -f "$watch_pid_file" ]; then
        local dp; dp=$(cat "$watch_pid_file" 2>/dev/null)
        if [ -n "$dp" ] && kill -0 "$dp" 2>/dev/null; then
            return 0
        fi
    fi

    # rc17: 如果 pidfile 丢了但 supervisor/guard 进程真实存在, 修复 pidfile, 不再重复拉起.
    if [ "$dpid_launcher" = "$dpid_supervisor" ] || [ "$dpid_launcher" = "$dpid_guard" ]; then
        local live_gp
        live_gp=$(ps -ef 2>/dev/null | grep -E '[h]nc_dpid_supervisor|[h]nc_dpid_guard\.sh' | awk 'NR==1{print $2}')
        if [ -n "$live_gp" ] && kill -0 "$live_gp" 2>/dev/null; then
            echo "$live_gp" > "$dpid_guard_pid_file" 2>/dev/null || true
            log "dpid: launcher live without pidfile, repaired pidfile pid=$live_gp"
            return 0
        fi
    fi

    # 冷却防止"反复死反复拉"
    local now; now=$(date +%s 2>/dev/null) || now=0
    local since=$((now - DPID_LAST_RESTART))
    if [ "$DPID_LAST_RESTART" -gt 0 ] && [ "$since" -lt 30 ]; then
        return 0
    fi

    log "dpid: process gone, relaunching launcher=$dpid_launcher"
    rm -f "$watch_pid_file" 2>/dev/null
    if [ "$dpid_launcher" = "$dpid_supervisor" ] || [ "$dpid_launcher" = "$dpid_guard" ]; then
        nohup "$dpid_launcher" >> "$HNC_DIR/logs/dpid_guard.log" 2>&1 &
        echo $! > "$dpid_guard_pid_file"
        log "dpid: launcher relaunched (PID: $(cat "$dpid_guard_pid_file" 2>/dev/null))"
    else
        nohup "$dpid_bin" -config "$HNC_DIR/etc/dpi_config.json" \
            >> "$HNC_DIR/logs/dpid.log" 2>&1 &
        echo $! > "$dpid_pid_file"
        log "dpid: relaunched (PID: $(cat "$dpid_pid_file" 2>/dev/null))"
    fi
    DPID_LAST_RESTART=$now
    return 0
}

check_services() {
    local restarted=0
    local now; now=$(date +%s 2>/dev/null) || now=0

    # ═══════════════════════════════════════════════════════════
    # v3.5.2 P0-A 修复:优先级检查架构
    # ═══════════════════════════════════════════════════════════
    # 之前:两个独立的 if 检查 hotspotd.pid 和 detect.pid,都独立触发重启。
    # 问题:detect.pid 和 hotspotd.pid 可能存同一个 PID(service.sh 的
    #      旧逻辑),hotspotd 崩溃后 watchdog 两个 if 都触发 → 同时启动
    #      C daemon + shell fallback → 并发写 devices.json.tmp → JSON 破损。
    # 修复:改成优先级架构:
    #      1) 先检查 hotspotd.pid,如果文件存在且进程活着 → OK,skip detect 检查
    #      2) hotspotd.pid 文件存在但进程死了 → 重启 hotspotd
    #      3) hotspotd.pid 文件不存在 → 说明当前是 shell fallback 模式,检查 detect.pid
    # 这保证在任何一个时刻,watchdog 只关心一个进程,不会"双重复活"。
    # ═══════════════════════════════════════════════════════════
    # v4.0.0-patch1.5 重要修正: httpd 拉起逻辑已从本函数移出到 ensure_httpd_running,
    # 主循环单独调用。之前 hotspotd 健康就 return 0,httpd 永远不被拉起是 bug。

    local hpid; hpid=$(cat "$RUN/hotspotd.pid" 2>/dev/null)
    if [ -n "$hpid" ]; then
        # hotspotd 路径
        if kill -0 "$hpid" 2>/dev/null; then
            prune_duplicate_hotspotd
            return 0
        fi
        # hotspotd 死了,尝试重启
        if [ -x "$HNC_DIR/bin/hotspotd" ]; then
            local since=$((now - HOTSPOTD_LAST_RESTART))
            if [ $since -lt $RESTART_COOLDOWN ]; then
                log "hotspotd dead but in cooldown (${since}s < ${RESTART_COOLDOWN}s),skip"
                return 0
            fi
            log "hotspotd dead, restarting (last=${HOTSPOTD_LAST_RESTART})..."
            local spawnlock="$RUN/daemon.spawn"
            if ! try_spawn_lock "$spawnlock"; then
                log "daemon spawn lock held, skip this round"
                return 0
            fi
            "$HNC_DIR/bin/hotspotd" -d >> "$HNC_DIR/logs/hotspotd.log" 2>&1 &
            sleep 1
            prune_duplicate_hotspotd
            rmdir "$spawnlock" 2>/dev/null
            HOTSPOTD_LAST_RESTART=$now
            restarted=1
        else
            rm -f "$RUN/hotspotd.pid"
            log "hotspotd binary missing, cleared stale pid file"
        fi
        return $restarted
    fi

    # hotspotd.pid 不存在:shell fallback 模式,检查 detect.pid
    local det_pid; det_pid=$(cat "$RUN/detect.pid" 2>/dev/null)
    if [ -n "$det_pid" ] && ! kill -0 "$det_pid" 2>/dev/null; then
        local since=$((now - DETECT_LAST_RESTART))
        if [ $since -lt $RESTART_COOLDOWN ]; then
            log "Detector dead but in cooldown (${since}s),skip"
        else
            log "Detector dead, restarting..."
            local spawnlock="$RUN/daemon.spawn"
            if try_spawn_lock "$spawnlock"; then
                sh "$HNC_DIR/bin/device_detect.sh" daemon >> "$HNC_DIR/logs/detect.log" 2>&1 &
                echo $! > "$RUN/detect.pid"
                sleep 1
                rmdir "$spawnlock" 2>/dev/null
                DETECT_LAST_RESTART=$now
                restarted=1
            fi
        fi
    elif [ -z "$det_pid" ]; then
        # rc2 修 S10: 两个 pid 文件都缺的兜底.
        # 原来: hotspotd.pid 和 detect.pid 都不存在 → 函数 return 0, 什么都不做,
        #       C daemon / shell fallback 都永远不起来. 真机事故: 用户手动 pkill + rm pid
        #       后 watchdog 看着在跑但再也不恢复, 必须重启模块.
        # 现在: 拉 device_detect daemon (自己会尝试起 C daemon, 失败回落 shell).
        local since=$((now - DETECT_LAST_RESTART))
        if [ $since -ge $RESTART_COOLDOWN ]; then
            log "both hotspotd.pid and detect.pid missing, bootstrapping detector"
            local spawnlock="$RUN/daemon.spawn"
            if try_spawn_lock "$spawnlock"; then
                sh "$HNC_DIR/bin/device_detect.sh" daemon >> "$HNC_DIR/logs/detect.log" 2>&1 &
                echo $! > "$RUN/detect.pid"
                sleep 1
                rmdir "$spawnlock" 2>/dev/null
                DETECT_LAST_RESTART=$now
                restarted=1
            fi
        fi
    fi

    return $restarted
}

# ── v4.0.0-patch1.5 ensure_httpd_running ─────────────────────
# 独立函数,主循环在 PENDING→ACTIVE 转移后 / ACTIVE 稳态每轮调用。
# 从 check_services 抽出,因为之前嵌在里面会被 "hotspotd 健康 return 0"
# 提前退出,导致 httpd 永远不被拉起(真机事故 #3)。
#
# 行为:
#   1. httpd.pid 进程死了 → 清 pid 文件,准备重拉
#   2. httpd.wanted marker 存在 + 进程没跑 → 用当前 iface + IP 拉
#   3. 校验 iface + IP + RFC1918(跟 patch1.4 的四层校验一致)
httpd_guard_remove() {
    iptables -D INPUT -p tcp --dport "$HNC_HTTPS_PORT" -j HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -F HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -X HNC_HTTPD_GUARD 2>/dev/null || true
}

httpd_guard_install() {
    local iface="$1" ip="$2"
    [ -z "$iface" ] && return 1
    iptables -N HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -F HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$HNC_HTTPS_PORT" -j HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -I INPUT 1 -p tcp --dport "$HNC_HTTPS_PORT" -j HNC_HTTPD_GUARD 2>/dev/null || true
    iptables -A HNC_HTTPD_GUARD -i lo -j ACCEPT 2>/dev/null || true
    iptables -A HNC_HTTPD_GUARD -i "$iface" -j ACCEPT 2>/dev/null || true
    iptables -A HNC_HTTPD_GUARD -j DROP 2>/dev/null || true
    log "httpd guard installed: ${HNC_HTTPS_PORT} allowed from hotspot iface=$iface ip=$ip/hotspot iface only; dropped elsewhere"
}

# hotfix17.8: PID 复用保护。kill -0 只能证明“这个 PID 存在”,不能证明它还是 hnc_httpd。
is_hnc_httpd_pid() {
    local pid="$1" cmd
    [ -n "$pid" ] || return 1
    [ -r "/proc/$pid/cmdline" ] || return 1
    cmd=$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    echo "$cmd" | grep -q 'hnc_httpd'
}

ensure_httpd_running() {
    local wpid; wpid=$(cat "$RUN/httpd.pid" 2>/dev/null)
    if [ -n "$wpid" ] && ! kill -0 "$wpid" 2>/dev/null; then
        log "httpd dead (was PID $wpid), removing pid file"
        rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip"
        wpid=""
    elif [ -n "$wpid" ] && ! is_hnc_httpd_pid "$wpid"; then
        log "httpd pid $wpid belongs to another process, clearing stale pid file"
        rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip"
        wpid=""
    fi

    # 不需要拉?退出
    [ ! -f "$RUN/httpd.wanted" ] && return 0
    [ -n "$wpid" ] && return 0   # 已经在跑

    local httpd_bin="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
    [ -x "$httpd_bin" ] || {
        log "httpd launch failed: binary missing at $httpd_bin"
        return 1
    }

    # v5.0: 检查 remote_enabled 决定是否绑热点 IP
    # loopback 段永远开 (本机 WebUI 需要)
    local remote_on
    remote_on=$(grep -o '"remote_enabled"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$HNC_DIR/data/rules.json" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')

    if [ "$remote_on" = "true" ]; then
        # rc3.1.6: 改绑 0.0.0.0 · 原因: ColorOS tether iface 主机 IP 和 gateway IP 不同
        # (主机 .67, gateway .1), 单独绑 .67 则连接设备访问 .1 会 ADDRESS_UNREACHABLE.
        # 0.0.0.0 监听所有接口, .1/.67/任何 IP 都能连. 已有 PIN+cookie 双层鉴权.
        # 仍然写实际 httpd_bind_ip marker 用当前 iface 的 IP (drift 检测用).
        local probe_out httpd_iface httpd_ip
        probe_out=$(probe_valid_hotspot) || {
            log "httpd launch deferred (remote_on): no valid hotspot yet. starting loopback-only for now."
            httpd_guard_remove
            "$httpd_bin" -loopback-port "$HNC_LOOPBACK_PORT" -hnc-dir "$HNC_DIR" \
                >> "$HNC_DIR/logs/httpd.log" 2>&1 &
            echo $! > "$RUN/httpd.pid"
            echo "loopback-only" > "$RUN/httpd_bind_ip"
            log "httpd launched (PID=$(cat "$RUN/httpd.pid"), loopback-only · 等热点就绪会重启)"
            return 0
        }
        httpd_iface=$(echo "$probe_out" | awk '{print $1}')
        httpd_ip=$(echo "$probe_out" | awk '{print $2}')
        httpd_guard_install "$httpd_iface" "$httpd_ip"
        log "starting httpd on 0.0.0.0:${HNC_HTTPS_PORT} (all ifaces) + loopback:${HNC_LOOPBACK_PORT} (hotspot iface=$httpd_iface ip=$httpd_ip)"
        "$httpd_bin" -bind 0.0.0.0 -port "$HNC_HTTPS_PORT" -loopback-port "$HNC_LOOPBACK_PORT" \
            -hnc-dir "$HNC_DIR" -http-port "$HNC_HTTP_REDIR_PORT" \
            >> "$HNC_DIR/logs/httpd.log" 2>&1 &
        echo $! > "$RUN/httpd.pid"
        echo "$httpd_ip" > "$RUN/httpd_bind_ip"
        log "httpd launched (PID=$(cat "$RUN/httpd.pid"), bound=0.0.0.0:${HNC_HTTPS_PORT} · hotspot ip=$httpd_ip)"
    else
        # 仅 loopback, 不需要热点 IP
        httpd_guard_remove
        log "starting httpd loopback-only on 127.0.0.1:${HNC_LOOPBACK_PORT}"
        "$httpd_bin" -loopback-port "$HNC_LOOPBACK_PORT" -hnc-dir "$HNC_DIR" \
            >> "$HNC_DIR/logs/httpd.log" 2>&1 &
        echo $! > "$RUN/httpd.pid"
        echo "loopback-only" > "$RUN/httpd_bind_ip"
        log "httpd launched (PID=$(cat "$RUN/httpd.pid"), loopback-only)"
    fi
}

# ── v4.0.0-patch1.4 httpd IP 漂移检测 ────────────────────────────
# 场景: httpd 启动时绑 IP=A, 后来热点重启 / IP 续租失败 / tethering 切换
#       iface IP 变成 B, 但 httpd 还在绑 A 上面。TCP 握手从 B 打到 A
#       被 Linux 拒,变成 ERR_CONNECTION_REFUSED。
# 对策: 每次健康检查对比 $RUN/httpd_bind_ip 和 当前 iface IP。
#       不等 → pkill httpd,下一轮 ensure_httpd_running 会用新 IP 拉起。
check_httpd_bind_drift() {
    [ -f "$RUN/httpd.pid" ]      || return 0
    [ -f "$RUN/httpd_bind_ip" ]  || return 0
    local wpid bound_ip
    wpid=$(cat "$RUN/httpd.pid" 2>/dev/null)
    [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null || return 0
    bound_ip=$(cat "$RUN/httpd_bind_ip" 2>/dev/null)
    [ -z "$bound_ip" ] && return 0

    local remote_on
    remote_on=$(grep -o '"remote_enabled"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$HNC_DIR/data/rules.json" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')

    # v5.3.0-rc8 P0: httpd is launched on 0.0.0.0 when remote is enabled.
    # Interface IP movement is transparent to a wildcard listener, so do not
    # kill hnc_httpd for DHCP renewal / tethering IP churn. Only relaunch for
    # the two real configuration transitions below.

    # Scenario 1: remote toggled OFF, httpd is still public.
    if [ "$remote_on" != "true" ] && [ "$bound_ip" != "loopback-only" ]; then
        log "httpd remote disabled by user: closing ${HNC_HTTPS_PORT} listener (loopback stays)"
        kill -9 "$wpid" 2>/dev/null
        rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip"
        httpd_guard_remove
        return 0
    fi

    # Scenario 2: remote toggled ON, httpd is loopback-only and hotspot exists.
    if [ "$remote_on" = "true" ] && [ "$bound_ip" = "loopback-only" ]; then
        local current_iface current_ip
        current_iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
        [ -z "$current_iface" ] && return 0
        [ "$current_iface" = "wlan0" ] && return 0
        current_ip=$(ip -4 addr show "$current_iface" 2>/dev/null | \
            awk '/inet /{split($2,a,"/");print a[1];exit}')
        [ -z "$current_ip" ] && return 0
        log "httpd bind upgrade: loopback-only -> 0.0.0.0 (remote_enabled=true, hotspot ip=$current_ip), relaunch"
        kill -9 "$wpid" 2>/dev/null
        rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip"
        return 0
    fi

    return 0
}

# ── Doze 检测 ────────────────────────────────────────────────
is_doze() {
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

# probe_valid_hotspot: 严格探测当前是否有合法热点接口
# 成功: stdout 输出 "<iface> <ip>", 返回 0
# 失败: 无输出,返回 1
# 5 道校验:探到 → 非空 → 非 wlan0 → 有 IPv4 → IPv4 是 RFC1918 私网
probe_valid_hotspot() {
    local iface ip
    iface=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null)
    [ -z "$iface" ]        && return 1
    [ "$iface" = "wlan0" ] && return 1   # 第二道防线
    ip=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
    [ -z "$ip" ] && return 1
    case "$ip" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) ;;
        *) return 1 ;;
    esac
    echo "$iface $ip"
    return 0
}

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
    if ! watchdog_tc_core_supported; then
        watchdog_mark_tc_unsupported_once tc_htb
        log "do_full_init: tc skipped because tc_htb=false; iptables only"
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
    # 写 rules.json.hotspot_iface,给 WebUI 显示
    sh "$HNC_DIR/bin/json_set.sh" top hotspot_iface "$iface" >> "$LOG" 2>&1
    # 转移前必须先清健康检查缓存,不然下一轮 check_health 用旧数据
    _HEALTH_TS=0
    echo "ACTIVE:$iface" > "$STATE_FILE"
    log "STATE entered ACTIVE:$iface"

    # rc3.1.31 Bug B gap 修复 · 冷启动 do_full_init 可能跑在客户端连上热点前,
    # 此时 devices.json 是空的 → restore_rules 拿不到 live IP 走了 rules.json 的
    # stale fallback → tc u32 filter 装到了旧 IP → Mi-10 新 IP 流量不 match.
    # 15s 后再跑一次 restore, 给 hotspotd 写 devices.json 的时间, get_current_ip
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
    ) &
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
            _HEALTH_TS=0
            return $tc_init_rc
        fi
        sh "$HNC_DIR/bin/tc_manager.sh" restore >> "$LOG" 2>&1
        sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1
    else
        watchdog_mark_tc_unsupported_once tc_htb
        log "do_migrate: tc skipped because tc_htb=false"
    fi
    sh "$HNC_DIR/bin/json_set.sh" top hotspot_iface "$new" >> "$LOG" 2>&1
    # 杀 httpd 让下轮 ensure_httpd_running 拿新 IP 重绑
    local wpid; wpid=$(cat "$RUN/httpd.pid" 2>/dev/null)
    if [ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null; then
        kill -9 "$wpid" 2>/dev/null
        log "killed old httpd PID=$wpid for rebind"
    fi
    rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip"
    _HEALTH_TS=0
    echo "ACTIVE:$new" > "$STATE_FILE"
    log "STATE entered ACTIVE:$new"
}

# ═══════════════════════════════════════════════════════════════════════════
# rc30.1: action mode — invoked by the Go hnc_watchdog binary to execute
# individual business actions WITHOUT entering the legacy `while true` main
# loop. The legacy loop remains intact below as a fallback when this script
# is invoked directly (no $1) by service.sh on systems where hnc_watchdog
# binary is absent.
#
# Contract:
#   sh watchdog.sh action <name> [args...]
#   exit code = action's return code (0 = ok, non-zero = failure)
#   stdout = action's output (used by callers that parse it, e.g. probe_hotspot)
#
# Must be placed AFTER all function definitions, but BEFORE the main loop
# initialization (which writes pidfiles, state files, and starts logging).
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
        probe_hotspot)        probe_valid_hotspot              ; exit $? ;;
        check_health)         check_health                     ; exit $? ;;
        full_restore)         full_restore "${1:-go_request}"  ; exit $? ;;
        full_init)            do_full_init "$1" "$2"           ; exit $? ;;
        migrate)              do_migrate "$1" "$2" "$3"        ; exit $? ;;
        cleanup_stale_rules)  cleanup_stale_rules_daily        ; exit $? ;;
        rotate_logs)          rotate_logs_periodic             ; exit $? ;;
        capability_probe)     run_capability_probe_active "$1" ; exit $? ;;
        tc_uplink_healthy)    ensure_tc_uplink_healthy         ; exit $? ;;
        httpd_drift)          check_httpd_bind_drift           ; exit $? ;;
        is_doze)              is_doze                          ; exit $? ;;
        get_iface)            get_iface                        ; exit $? ;;
        prune_dup_hotspotd)   prune_duplicate_hotspotd         ; exit $? ;;
        *) echo "watchdog.sh action: unknown command '$_action'" >&2; exit 64 ;;
    esac
fi

# ── 主循环 v4.0.0-patch1.5: Defer Init 状态机 ────────────────
log "=== Watchdog v4.0.0-patch1.5 started (PID=$$) ==="
echo $$ > "$RUN/watchdog.pid"

# v3.4.1: 彻底删除 ip monitor 事件监听
# v1.5: 状态机驱动。初始从 $STATE_FILE 读,崩溃重启时能恢复
INITIAL_STATE=$(cat "$STATE_FILE" 2>/dev/null)
if [ -z "$INITIAL_STATE" ]; then
    INITIAL_STATE="PENDING"
    echo "PENDING" > "$STATE_FILE"
fi
log "initial state: $INITIAL_STATE"

RESTORE_COUNT=0
INTERVAL=$INTERVAL_NORMAL
RECOVERY_ROUNDS=0
LAST_V6_SYNC=0
LAST_STATS_SAMPLE=0
STATS_INTERVAL=300
# RESTORE 速率限制(只在 ACTIVE 状态生效)
RESTORE_WINDOW_START=0
RESTORE_WINDOW_COUNT=0
RESTORE_WINDOW_MAX=3
RESTORE_WINDOW_SEC=300
RESTORE_WINDOW_SEC_MAX=3600
RESTORE_CONSEC_WINDOWS=0
LAST_PASSIVE_EXIT_TS=0
PASSIVE_MODE=0
PASSIVE_LOGGED=0
PASSIVE_MARKER="$RUN/watchdog_passive.marker"

# 探测节流: PENDING 状态下每 10 秒探一次(为了快速启动);
# PENDING 状态每 10 秒探一次(热点刚开、还没客户端时),避免 60 秒才试一次导致
# 开机后 1 分钟以上热点才能被使用。ACTIVE 稳态沿用主循环 $INTERVAL(60s)。
# rc38: 删死变量 PROBE_INTERVAL_ACTIVE(全脚本 0 引用,稳态实际走 $INTERVAL)。
PROBE_INTERVAL_PENDING=10

# rc3.1.5 修: 进 main loop 前立即 ensure httpd_running, 不等第一次 sleep 完.
# 之前 watchdog 启动后要先 sleep 60-120s 才第一次 ensure httpd, 导致用户点 toggle
# 经常撞上"启动窗口"失败 (curl 8444 connection refused).
# 这个修法让 httpd 在 watchdog 启动后 ~1s 内就上线.
log "bootstrap: ensure httpd before loop entry"
ensure_httpd_running 2>/dev/null || log "bootstrap: ensure_httpd_running failed (will retry in loop)"

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


while true; do
    # 读当前状态(每轮读,因为 do_full_init / do_migrate 会改文件)
    STATE=$(cat "$STATE_FILE" 2>/dev/null || echo "PENDING")

    # rc3.1: service.wanted marker 逻辑已移除 · watchdog 在 cleanup.sh 杀进程
    # 阶段就已经死了, 这段永远执行不到. restart 改由 cleanup.sh 末尾直接 fork.

    # rc3.1.30 · 首轮跳过 sleep, 立即跑 dispatch.
    # 配合 post-fs-data.sh 清 hnc_state, 重启后 watchdog 启动即 probe + do_full_init
    # 不用等 10s (PROBE_INTERVAL_PENDING). 用户开热点后连上客户端立即有规则 · 不会
    # 出现"前 10s 无限速"的窗口.
    if [ "${FIRST_ROUND:-1}" = "1" ]; then
        FIRST_ROUND=0
    else
        # 根据状态决定 sleep 时长
        case "$STATE" in
            PENDING) sleep $PROBE_INTERVAL_PENDING ;;
            ACTIVE:*) sleep $INTERVAL ;;
            *) log "WARN: unknown state '$STATE', resetting to PENDING"
               echo "PENDING" > "$STATE_FILE"
               STATE="PENDING"
               sleep $PROBE_INTERVAL_PENDING ;;
        esac
    fi

    # Doze 模式: 降频并跳过主动动作
    cleanup_stale_rules_daily

    if is_doze; then
        INTERVAL=$INTERVAL_DOZE
        continue
    fi

    # ═══ 状态机 dispatch ═══════════════════════════════════════
    case "$STATE" in

    PENDING)
        # 没初始化过,探测热点
        # rc3.1.31 隐患 3 诊断: 记 probe 耗时. reviewer 提醒如果 probe 本身 >3s,
        # FIRST_ROUND=1 立刻 probe 的效果就被抵消了. 真机 probe_valid_hotspot 只
        # 调 device_detect.sh iface (读文件 + 少量命令) 预期 <100ms. 若 probe.ms
        # 持续 >1000ms 需单独优化.
        _probe_t0=$(date +%s%N 2>/dev/null)
        probe_out=$(probe_valid_hotspot)
        probe_rc=$?
        _probe_t1=$(date +%s%N 2>/dev/null)
        if [ -n "$_probe_t0" ] && [ -n "$_probe_t1" ]; then
            _probe_ms=$(( (_probe_t1 - _probe_t0) / 1000000 ))
            [ "$_probe_ms" -gt 500 ] && log "probe_valid_hotspot slow: ${_probe_ms}ms (rc=$probe_rc)"
        fi
        if [ $probe_rc -eq 0 ]; then
            new_iface=$(echo "$probe_out" | awk '{print $1}')
            new_ip=$(echo "$probe_out" | awk '{print $2}')
            do_full_init "$new_iface" "$new_ip"
            # init 后同轮不做 check_health(规则刚挂,health 缓存无意义)
            ensure_httpd_running
        fi
        # 没探到就继续等,什么都不做
        ;;

    ACTIVE:*)
        active_iface="${STATE#ACTIVE:}"

        # 探测当前热点状态
        probe_out=$(probe_valid_hotspot)
        probe_rc=$?

        if [ $probe_rc -ne 0 ]; then
            # 热点关了/消失了: 保持 ACTIVE 状态(用户可能只是临时关),
            # 不做 migrate(不知道迁移到哪),也不 full_restore(规则挂的
            # iface 已经 down, 没意义)。下轮再探。
            # 不 log(避免每 60s 刷屏),除非这是第一次发现
            # rc2 修 S4: continue 前先跑 check_services/heartbeat/rotate_logs_periodic,
            #          否则热点关着时这些 housekeeping 全被跳, watchdog 看着像挂了
            check_services
            heartbeat
            rotate_logs_periodic
            continue
        fi

        new_iface=$(echo "$probe_out" | awk '{print $1}')
        new_ip=$(echo "$probe_out" | awk '{print $2}')

        # iface 变了 → 迁移
        if [ "$new_iface" != "$active_iface" ]; then
            do_migrate "$active_iface" "$new_iface" "$new_ip"
            ensure_httpd_running
            continue
        fi

        run_capability_probe_active "$new_iface"

        # 稳态: 健康检查 + httpd 维护
        check_health
        health_rc=$?

        if [ $health_rc -eq 2 ]; then
            # 临时故障(xtables busy),跳过本轮
            INTERVAL=$INTERVAL_NORMAL
        elif [ $health_rc -ne 0 ]; then
            # 规则丢了: 走速率限制 → full_restore
            NOW_RL=$(date +%s)
            CUR_WINDOW_SEC=$RESTORE_WINDOW_SEC
            if [ $RESTORE_CONSEC_WINDOWS -gt 0 ]; then
                CUR_WINDOW_SEC=$((RESTORE_WINDOW_SEC * (1 << RESTORE_CONSEC_WINDOWS)))
                [ $CUR_WINDOW_SEC -gt $RESTORE_WINDOW_SEC_MAX ] && CUR_WINDOW_SEC=$RESTORE_WINDOW_SEC_MAX
            fi
            if [ $((NOW_RL - RESTORE_WINDOW_START)) -ge $CUR_WINDOW_SEC ]; then
                RESTORE_WINDOW_START=$NOW_RL
                RESTORE_WINDOW_COUNT=0
                if [ $PASSIVE_MODE -eq 1 ]; then
                    if [ $((NOW_RL - LAST_PASSIVE_EXIT_TS)) -lt $((RESTORE_WINDOW_SEC * 2)) ]; then
                        RESTORE_CONSEC_WINDOWS=$((RESTORE_CONSEC_WINDOWS + 1))
                        log "exiting passive but re-triggering soon (consec=$RESTORE_CONSEC_WINDOWS)"
                    else
                        RESTORE_CONSEC_WINDOWS=0
                    fi
                    log "exiting passive mode"
                    PASSIVE_MODE=0
                    PASSIVE_LOGGED=0
                    LAST_PASSIVE_EXIT_TS=$NOW_RL
                    rm -f "$PASSIVE_MARKER" 2>/dev/null
                fi
            fi
            if [ $PASSIVE_MODE -eq 1 ]; then
                if [ $PASSIVE_LOGGED -eq 0 ]; then
                    log "health_fail in passive mode, skipping restore"
                    PASSIVE_LOGGED=1
                fi
                INTERVAL=$INTERVAL_NORMAL
            else
                RESTORE_WINDOW_COUNT=$((RESTORE_WINDOW_COUNT+1))
                RESTORE_COUNT=$((RESTORE_COUNT+1))
                full_restore "health_fail (total=$RESTORE_COUNT, window=$RESTORE_WINDOW_COUNT/$RESTORE_WINDOW_MAX, win_sec=$CUR_WINDOW_SEC)"
                if [ $RESTORE_WINDOW_COUNT -ge $RESTORE_WINDOW_MAX ]; then
                    log "RESTORE window limit hit, entering passive mode"
                    PASSIVE_MODE=1
                    touch "$PASSIVE_MARKER" 2>/dev/null
                fi
                INTERVAL=$INTERVAL_RECOVERY
                RECOVERY_ROUNDS=3
            fi
        else
            # health 正常
            if [ "$RECOVERY_ROUNDS" -gt 0 ]; then
                RECOVERY_ROUNDS=$((RECOVERY_ROUNDS-1))
                [ "$RECOVERY_ROUNDS" -eq 0 ] && INTERVAL=$INTERVAL_NORMAL
            else
                INTERVAL=$INTERVAL_NORMAL
            fi
        fi

        # v6 同步(每 60s 兜底一次)
        NOW=$(date +%s)
        if [ $((NOW - LAST_V6_SYNC)) -ge 60 ]; then
            sh "$HNC_DIR/bin/v6_sync.sh" sync >> "$LOG" 2>&1 || true
            LAST_V6_SYNC=$NOW
        fi

        # 流量统计采样
        if [ $((NOW - LAST_STATS_SAMPLE)) -ge $STATS_INTERVAL ]; then
            sh "$HNC_DIR/bin/stats_sample.sh" >> "$LOG" 2>&1 || true
            LAST_STATS_SAMPLE=$NOW
        fi

        # httpd IP 漂移检测
        check_httpd_bind_drift

        # httpd 保活(拉起新进程)
        ensure_httpd_running

        # v5.1 RC1: 主动 uplink 健康检查
        ensure_tc_uplink_healthy
        ;;
    esac

    # 子服务存活检查(hotspotd / device detect, 跟状态无关)
    check_services

    # v5.3.0-rc12: dpid 存活检查
    ensure_dpid_running

    # v4.0 Patch 1.6 稳定性卫生
    heartbeat
    rotate_logs_periodic

done

# trap EXIT 会 fire 如果执行到这里(不应发生)
