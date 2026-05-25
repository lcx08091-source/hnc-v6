#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
# cleanup.sh — HNC 资源完全释放
# 在模块禁用/卸载/手动调用时执行，确保无残留进程和规则

HNC_DIR=${HNC_DIR:-/data/local/hnc}
RUN=$HNC_DIR/run
LOG=$HNC_DIR/logs/service.log

log() { echo "[$(TZ=Asia/Shanghai date '+%H:%M:%S')] [CLEANUP] $1" >> $LOG; }

# rc3 修 N-15: mode dispatch
# rules   - 只清 tc/iptables 规则, 保留进程 + JSON 数据 (WebUI "清空限速规则")
# all     - 全清 + 杀所有进程 (默认, 模块卸载用)
# restart - 同 all + 留 service.wanted marker 让 service.sh 重启
# 旧行为等价于 MODE=all, 向后兼容: 无参 = all
MODE="${1:-all}"
case "$MODE" in
    rules|all|restart|safe_release) ;;
    *)
        echo "cleanup.sh: unknown mode '$MODE' (rules|all|restart|safe_release)" >&2
        exit 2
        ;;
esac
log "=== Cleanup started (mode=$MODE) ==="

# v5.3.0-rc13 safety gate:
# Historical WebUI/old hnc_httpd calls cleanup.sh all for the visible
# “释放所有资源” button.  That killed hnc_httpd/watchdog and made re-entry fail.
# Treat bare all as safe restart unless a real uninstall/full-stop path opts in.
if [ "$MODE" = "all" ] && [ "${HNC_ALLOW_FULL_STOP:-0}" != "1" ] && [ "${HNC_UNINSTALL:-0}" != "1" ]; then
    MODE=restart
    log "all mode without HNC_ALLOW_FULL_STOP/HNC_UNINSTALL: using safe restart"
fi

# rc3.1.13.2 修 P1 (review §2): rules mode 下不杀 watchdog,
# 60s 后 watchdog full_restore 把规则全恢复 = 用户清规则白清.
# 设 marker 让 watchdog skip restore 一段时间, marker 过期后恢复.
# 由于 mode=rules 的语义本来就是 "保留进程 + 清规则给用户重配", marker 600s
# 给用户充裕时间重新设. 用户重启 service 或再次 cleanup all 时 marker 自动清.
if [ "$MODE" = "rules" ]; then
    mkdir -p "$RUN" 2>/dev/null
    date +%s > "$RUN/cleanup_rules.marker" 2>/dev/null
    log "rules mode: set restore-suppress marker (600s)"
fi

if [ "$MODE" = "safe_release" ]; then
    MODE=restart
    log "safe_release alias: cleanup resources then respawn service.sh"
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "restart" ]; then
# ── 1. 停止所有 HNC 进程 (rules 模式跳过) ────────────────────
# rc3.1.33 修 #20: watchdog 提到首位.
# 之前顺序 `hotspotd watchdog detect ...` 错: 先杀 hotspotd, 但 watchdog 还活,
# 在下一行 kill watchdog 之前的 ms 窗口内 watchdog 的 check_services 可能看到
# hotspotd.pid 文件被删 → 触发 hotspotd 重启 → cleanup 完成后 hotspotd 复活.
# 正确做法: 先杀看护进程 (watchdog), 再杀被看护的子进程, 避免被 "复活".
# netmon/api 是 v3.x 历史残留 (api/server.sh 已弃用), 保留只是为了清理可能的旧
# 残留 PID 文件, 不会真有进程在跑.
#
# rc3.1.34 修 #21: 之前 `kill PID` (SIGTERM) + `sleep 1` 不等真死, 直接走下面
# tc/iptables 清理. hotspotd 收 SIGTERM 后进 cleanup 路径会调 mdns_worker stop
# (Bug #8: 最坏阻塞 25.6s 等队列任务跑完), 期间 socket 还存在 / 可能还在写
# devices.json. 我们 cleanup 已经在删 socket / 清 tc 规则 → 竞态.
# 修法: 收集所有要杀的 PID, SIGTERM 后 polling kill -0 等死, 最多 3s,
# 仍活的升级 SIGKILL. SIGKILL 内核直接回收, hotspotd 没机会跑 mdns_worker stop,
# 但反正我们要 cleanup 全清, 子进程清理路径跑完跑半都无关紧要.
PIDS_TO_WAIT=""
for pidfile in watchdog dpid_guard dpid.monitor dpid.child dpid hotspotd detect api hotspot netmon httpd; do
    PID=$(cat "$RUN/${pidfile}.pid" 2>/dev/null)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        log "TERM $pidfile (PID=$PID)"
        PIDS_TO_WAIT="$PIDS_TO_WAIT $PID:$pidfile"
    fi
    rm -f "$RUN/${pidfile}.pid"
done

# 等所有 PID 真死, 最多 3s (30 轮 × 100ms)
WAIT_ROUND=0
while [ $WAIT_ROUND -lt 30 ]; do
    STILL_ALIVE=""
    for entry in $PIDS_TO_WAIT; do
        pid_only=${entry%%:*}
        if kill -0 "$pid_only" 2>/dev/null; then
            STILL_ALIVE="$STILL_ALIVE $entry"
        fi
    done
    [ -z "$STILL_ALIVE" ] && break
    PIDS_TO_WAIT="$STILL_ALIVE"
    # busybox sleep 支持小数; toybox 也支持
    sleep 0.1 2>/dev/null || sleep 1
    WAIT_ROUND=$((WAIT_ROUND + 1))
done

# 仍活的: SIGKILL
for entry in $PIDS_TO_WAIT; do
    pid_only=${entry%%:*}
    name_only=${entry#*:}
    if kill -0 "$pid_only" 2>/dev/null; then
        kill -9 "$pid_only" 2>/dev/null
        log "KILL -9 $name_only (PID=$pid_only) - did not exit cleanly within 3s"
    fi
done

# rc2 修 S9: pkill -f 用完整 bin/xxx.sh 前缀而不是裸名.
#   原 "watchdog" 会匹配 cmdline 里任何含 "watchdog" 的进程 (例如用户在编辑器打开
#   watchdog.sh, 或其他模块路径含 watchdog). "bin/watchdog.sh" 把误杀面收窄到实际
#   含 HNC 脚本路径的进程.
# rc30.0+ : 加入 hnc_dpid_supervisor 和 hnc_watchdog (Go 二进制) 的清理.
for proc in bin/hnc_dpid_supervisor bin/hnc_dpid_guard.sh bin/hnc_watchdog bin/device_detect.sh bin/watchdog.sh bin/hotspot_autostart.sh; do
    pkill -f "$proc" 2>/dev/null && log "pkill $proc"
done
fi  # end MODE=all|restart 的进程清理分支

# ── 2. 清除 TC 规则 ──────────────────────────────────────────
IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null || echo wlan2)
log "Cleaning TC on $IFACE and ifb0..."
# v5.8.8 (audit): 只在 HNC 拥有该 iface 的 root qdisc 时才删(归属标记由 tc_manager
# 写,见 tc_root_owned_$iface),避免在 ColorOS 上误删系统/别的模块的 root qdisc。
# ingress/ifb0 是 HNC 上行整形自建的构件,属 HNC,正常清理。
if [ -f "$HNC_DIR/run/tc_root_owned_$IFACE" ]; then
    tc qdisc del dev "$IFACE" root 2>/dev/null
    rm -f "$HNC_DIR/run/tc_root_owned_$IFACE" 2>/dev/null
else
    log "skip root qdisc del on $IFACE (no HNC ownership marker)"
fi
tc qdisc del dev "$IFACE" ingress 2>/dev/null
tc qdisc del dev ifb0 root 2>/dev/null
ip link set ifb0 down 2>/dev/null
ip link del ifb0 2>/dev/null
log "TC cleanup done"

# ── 3. 清除 iptables 规则 ────────────────────────────────────
# v3.3.4：双栈清理 v4 + v6 所有 HNC 链
log "Cleaning iptables chains (v4+v6)..."
for table_chain in "mangle PREROUTING  HNC_RESTORE" \
                   "mangle FORWARD     HNC_MARK"    \
                   "mangle FORWARD     HNC_STATS"   \
                   "mangle POSTROUTING HNC_SAVE"    \
                   "filter FORWARD     HNC_CTRL"    \
                   "filter FORWARD     HNC_WHITELIST"; do
    t=$(echo $table_chain | awk '{print $1}')
    c=$(echo $table_chain | awk '{print $2}')
    h=$(echo $table_chain | awk '{print $3}')
    iptables -t $t -D $c -j $h 2>/dev/null
    iptables -t $t -F $h 2>/dev/null
    iptables -t $t -X $h 2>/dev/null
done

# v6 清理（v3.3.4 新增：完整清理 v6 所有链，不再只清 HNC_MARK）
if command -v ip6tables >/dev/null 2>&1; then
    for table_chain in "mangle PREROUTING  HNC_RESTORE" \
                       "mangle FORWARD     HNC_MARK"    \
                       "mangle POSTROUTING HNC_SAVE"    \
                       "filter FORWARD     HNC_CTRL"    \
                       "filter FORWARD     HNC_WHITELIST"; do
        t=$(echo $table_chain | awk '{print $1}')
        c=$(echo $table_chain | awk '{print $2}')
        h=$(echo $table_chain | awk '{print $3}')
        ip6tables -t $t -D $c -j $h 2>/dev/null
        ip6tables -t $t -F $h 2>/dev/null
        ip6tables -t $t -X $h 2>/dev/null
    done
fi
log "iptables cleanup done"

# ── 4. 清理临时文件（保留 data/ 目录，用户配置不删）────────
rm -f "$RUN"/*.pid "$RUN"/netevt_* "$RUN"/arp_hash "$RUN"/hotspotd.sock "$RUN"/dpid.netlink.event 2>/dev/null
rm -f "$HNC_DIR/run/hostname_cache" 2>/dev/null  # 缓存可以删
rm -rf "$HNC_DIR/run/v6" 2>/dev/null              # v3.4.0：v6_sync 快照目录
# v3.5.0 P2-5: 清理 device_detect.sh 留下的临时文件(进程异常退出后残留)
rm -f "$RUN"/scan_tmp.* "$RUN"/scan_arp.* "$RUN"/.gc_* "$RUN"/.lock_check_* 2>/dev/null
rm -rf "$RUN/json.lock" "$RUN/hnc_json.lock" 2>/dev/null  # P0-2 锁残留 + rc11 hnc_json stale lock
# v3.9.1: stats 临时文件 + 日期标记(stats_raw / stats_daily 是用户数据,不删)
rm -f "$RUN"/stats_map.* "$RUN"/rollup_names.* "$RUN"/rollup_agg.* 2>/dev/null
rm -f "$RUN"/stats_last_date 2>/dev/null
# v4.0.0-patch1.1: httpd 延迟启动 marker(watchdog 用)
rm -f "$RUN/httpd.wanted" 2>/dev/null
# v4.0.0-patch1.3: watchdog passive mode marker
rm -f "$RUN/watchdog_passive.marker" 2>/dev/null
# v4.0.0-patch1.4: httpd 绑定 IP marker(IP 漂移检测用)
rm -f "$RUN/httpd_bind_ip" 2>/dev/null
# v4.0.0-patch1.5: watchdog Defer Init 状态文件
# 清掉后下次 watchdog 启动会从 PENDING 重新开始
rm -f "$RUN/hnc_state" 2>/dev/null

# rc3.1 修 N-15R: 原 rc3 留 service.wanted marker 依赖 watchdog poll,
# 但 watchdog 在上面 kill 循环里已经死了, 没人读 marker.
# 改为直接 fork service.sh · nohup + & 脱离 cleanup.sh 生命周期
# (cleanup.sh exit 后 service.sh 仍活 + setsid 保留 session 独立).
if [ "$MODE" = "restart" ]; then
    SERVICE_SH=""
    # 路径 1 (首选): service.sh 启动时写的 $RUN/service.path
    if [ -f "$RUN/service.path" ]; then
        MODDIR_READ=$(cat "$RUN/service.path" 2>/dev/null)
        if [ -n "$MODDIR_READ" ] && [ -f "$MODDIR_READ/service.sh" ]; then
            SERVICE_SH="$MODDIR_READ/service.sh"
        fi
    fi
    # 路径 2 (兜底): KSU / SukiSU / Magisk 常见安装位置
    for c in /data/adb/modules/hotspot_network_control/service.sh \
             /data/adb/modules_update/hotspot_network_control/service.sh \
             /data/adb/hnc/service.sh; do
        if [ -z "$SERVICE_SH" ] && [ -f "$c" ]; then
            SERVICE_SH="$c"
        fi
    done
    if [ -n "$SERVICE_SH" ]; then
        log "restart: respawning $SERVICE_SH"
        nohup sh "$SERVICE_SH" >> "$LOG" 2>&1 &
        log "service.sh forked, new pid=$!"
    else
        log "ERROR: cannot locate service.sh for restart. 用户需手动 disable/enable 模块恢复"
    fi
fi

log "=== Cleanup complete ==="
if [ "$MODE" = "restart" ]; then
    echo "HNC: resources released and service restart scheduled"
else
    echo "HNC: all resources released"
fi
