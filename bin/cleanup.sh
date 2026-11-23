#!/system/bin/sh

# v3.5.0 alpha-0: PATH 健壮性,见 service.sh
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
# cleanup.sh — HNC 资源完全释放
# 在模块禁用/卸载/手动调用时执行，确保无残留进程和规则

HNC_DIR=${HNC_DIR:-/data/local/hnc}
if [ -f "$HNC_DIR/bin/hnc_env.sh" ]; then
    . "$HNC_DIR/bin/hnc_env.sh"
elif [ -f "${0%/*}/hnc_env.sh" ]; then
    . "${0%/*}/hnc_env.sh"
fi
if [ -f "$HNC_DIR/bin/hnc_proc.sh" ]; then
    . "$HNC_DIR/bin/hnc_proc.sh"
elif [ -f "${0%/*}/hnc_proc.sh" ]; then
    . "${0%/*}/hnc_proc.sh"
fi
RUN=$HNC_DIR/run
LOG=$HNC_DIR/logs/service.log

mkdir -p "$HNC_DIR/logs" 2>/dev/null
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)] [CLEANUP] $1" >> "$LOG" 2>/dev/null; }

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

# v5.18: offload 兜底撤销(limit_map 恢复 + 重新通知 hotspotd 受限设备), 否则
# 模块停掉后 tether offload 会一直被压在慢路径上。必须在杀 hotspotd 之前做
# (撤销走 hotspotd IPC); hotspotd 没在跑时 hnc_ipc 连不上即静默跳过。
if { [ "$MODE" = "all" ] || [ "$MODE" = "restart" ]; } && [ -f "$HNC_DIR/bin/hnc_offload_guard.sh" ]; then
    sh "$HNC_DIR/bin/hnc_offload_guard.sh" restore >/dev/null 2>&1 && log "offload guard restored"
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
_cleanup_is_service_sh_pid() {
    local _sp="$1" _proot="${HNC_PROC_ROOT:-/proc}" _comm="" _a0="" _a1=""
    case "$_sp" in ''|*[!0-9]*|0|1) return 1 ;; esac
    [ "$_sp" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_sp" = "$PPID" ] && return 1
    [ -r "$_proot/$_sp/cmdline" ] || return 1
    if [ -r "$_proot/$_sp/comm" ]; then
        _comm=$(tr -d '\r\n' < "$_proot/$_sp/comm" 2>/dev/null)
        case "$_comm" in
            ""|sh|mksh|ash|dash|busybox|toybox|service.sh) ;;
            *) return 1 ;;
        esac
    fi
    _a0=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '1p')
    _a1=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '2p')
    case "$_a0" in
        */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$HNC_DIR/service.sh")
            return 0
            ;;
    esac
    case "${_a0##*/}" in
        sh|mksh|ash|dash|busybox|toybox)
            [ "$_a1" = "-c" ] && return 1
            case "$_a1" in
                */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$HNC_DIR/service.sh")
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

_cleanup_is_hnc_script_pid() {
    local _sp="$1" _rel="$2" _proot="${HNC_PROC_ROOT:-/proc}" _bn _comm="" _a0="" _a1=""
    case "$_sp" in ''|*[!0-9]*|0|1) return 1 ;; esac
    [ "$_sp" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_sp" = "$PPID" ] && return 1
    [ -n "$_rel" ] && [ -r "$_proot/$_sp/cmdline" ] || return 1
    _bn="${_rel##*/}"
    if [ -r "$_proot/$_sp/comm" ]; then
        _comm=$(tr -d '\r\n' < "$_proot/$_sp/comm" 2>/dev/null)
        case "$_comm" in
            ""|sh|mksh|ash|dash|busybox|toybox|"$_bn") ;;
            *) return 1 ;;
        esac
    fi
    _a0=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '1p')
    _a1=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '2p')
    case "$_a0" in
        "$HNC_DIR/$_rel"|"/data/local/hnc/$_rel"|*/hotspot_net_ctl/"$_rel"|*/hotspot_network_control/"$_rel"|/data/adb/hnc/"$_rel")
            return 0
            ;;
    esac
    case "${_a0##*/}" in
        sh|mksh|ash|dash|busybox|toybox)
            [ "$_a1" = "-c" ] && return 1
            case "$_a1" in
                "$HNC_DIR/$_rel"|"/data/local/hnc/$_rel"|*/hotspot_net_ctl/"$_rel"|*/hotspot_network_control/"$_rel"|/data/adb/hnc/"$_rel")
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

_cleanup_pidfile_verified() {
    local _p="$1" _role="$2"
    case "$_role" in
        sentinel) _cleanup_is_service_sh_pid "$_p" ;;
        watchdog) pid_matches "$_p" hnc_watchdog || _cleanup_is_hnc_script_pid "$_p" "bin/watchdog.sh" ;;
        dpid_guard|launcher) pid_matches "$_p" hnc_launcher ;;
        dpid) pid_matches "$_p" hnc_dpid ;;
        hotspotd) pid_matches "$_p" hotspotd ;;
        hotspot) _cleanup_is_hnc_script_pid "$_p" "bin/hotspot_autostart.sh" || _cleanup_is_service_sh_pid "$_p" ;;
        httpd) pid_matches "$_p" hnc_httpd ;;
        *) return 1 ;;
    esac
}

PIDS_TO_WAIT=""
# v5.33 / RC2: 只列现在还有人写的 pidfile, 强制纯数字正整数校验 + 排除 $$/$PPID + pid_matches 精确身份核验!
for pidfile in sentinel watchdog dpid_guard launcher dpid hotspotd hotspot httpd; do
    PID=$(tr -d ' \t\r\n' < "$RUN/${pidfile}.pid" 2>/dev/null)
    rm -f "$RUN/${pidfile}.pid"
    case "$PID" in ''|*[!0-9]*|0|1) continue ;; esac
    [ "$PID" = "$$" ] && continue
    [ -n "${PPID:-}" ] && [ "$PID" = "$PPID" ] && continue
    if _cleanup_pidfile_verified "$PID" "$pidfile" && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        log "TERM $pidfile (PID=$PID)"
        PIDS_TO_WAIT="$PIDS_TO_WAIT $PID:$pidfile"
    fi
done

# 等所有 PID 真死, 最多 3s (30 轮 × 100ms)
WAIT_ROUND=0
while [ $WAIT_ROUND -lt 30 ]; do
    STILL_ALIVE=""
    for entry in $PIDS_TO_WAIT; do
        pid_only=${entry%%:*}
        case "$pid_only" in ''|*[!0-9]*|0|1) continue ;; esac
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
    case "$pid_only" in ''|*[!0-9]*|0|1) continue ;; esac
    [ "$pid_only" = "$$" ] && continue
    [ -n "${PPID:-}" ] && [ "$pid_only" = "$PPID" ] && continue
    if _cleanup_pidfile_verified "$pid_only" "$name_only" && kill -0 "$pid_only" 2>/dev/null; then
        kill -9 "$pid_only" 2>/dev/null
        log "KILL -9 $name_only (PID=$pid_only) - did not exit cleanly within 3s"
    fi
done

# RC2 P1-2: 移除宽泛的 pkill -f, 改用 /proc/<pid>/comm + argv[0] 精确身份匹配清理未登记孤儿进程
# (非 /data/local/hnc 单测沙箱且未显式指定 HNC_PROC_ROOT 时绝不扫描宿主机 /proc!)
_proot="${HNC_PROC_ROOT:-/proc}"
if [ "$_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
    _SWEEP_PIDS=""
    for _d in "$_proot"/[0-9]*; do
        [ -r "$_d/cmdline" ] || continue
        _p=${_d##*/}
        case "$_p" in ''|*[!0-9]*|0|1) continue ;; esac
        [ "$_p" = "$$" ] && continue
        [ -n "${PPID:-}" ] && [ "$_p" = "$PPID" ] && continue
        _matched=""
        for _bname in hnc_launcher hnc_watchdog hnc_dpid hotspotd hnc_httpd; do
            if pid_matches "$_p" "$_bname"; then
                _matched="$_bname"
                break
            fi
        done
        if [ -z "$_matched" ]; then
            for _sname in bin/hnc_offload_guard.sh bin/device_detect.sh bin/watchdog.sh bin/hotspot_autostart.sh; do
                if _cleanup_is_hnc_script_pid "$_p" "$_sname"; then
                    _matched="$_sname"
                    break
                fi
            done
        fi
        if [ -z "$_matched" ] && _cleanup_is_service_sh_pid "$_p"; then
            _matched="service.sh"
        fi
        if [ -n "$_matched" ]; then
            kill "$_p" 2>/dev/null && log "TERM orphan $_matched (PID=$_p)"
            _SWEEP_PIDS="$_SWEEP_PIDS $_p:$_matched"
        fi
    done
    if [ -n "$_SWEEP_PIDS" ]; then
        sleep 0.2 2>/dev/null || sleep 1
        for _se in $_SWEEP_PIDS; do
            _sp=${_se%%:*}
            _sn=${_se#*:}
            case "$_sp" in ''|*[!0-9]*|0|1) continue ;; esac
            [ "$_sp" = "$$" ] && continue
            [ -n "${PPID:-}" ] && [ "$_sp" = "$PPID" ] && continue
            if kill -0 "$_sp" 2>/dev/null; then
                kill -9 "$_sp" 2>/dev/null && log "KILL -9 orphan $_sn (PID=$_sp)"
            fi
        done
    fi
fi
fi  # end MODE=all|restart 的进程清理分支

# ── 2. 清除 TC 规则(覆盖当前活跃接口 + 历史迁移/缓存接口 + mq 子树/复用树残留)──
IFACE=$(sh "$HNC_DIR/bin/device_detect.sh" iface 2>/dev/null | tr -d '\r\n ')
_cand_ifaces="$IFACE"
for _if_f in "$RUN/active_iface" "$RUN/hotspot_iface" "$RUN/iface.cache"; do
    [ -f "$_if_f" ] && _cand_ifaces="$_cand_ifaces $(head -n 1 "$_if_f" 2>/dev/null | tr -d '\r\n ')"
done
for _mk_f in "$RUN"/tc_root_owned_*; do
    [ -e "$_mk_f" ] || continue
    _cand_ifaces="$_cand_ifaces ${_mk_f#"$RUN/tc_root_owned_"}"
done
for _mk_f in "$RUN"/tc_mq_child_*; do
    [ -e "$_mk_f" ] || continue
    _cand_ifaces="$_cand_ifaces ${_mk_f#"$RUN/tc_mq_child_"}"
done
[ -n "$IFACE" ] || IFACE=$(printf '%s\n' $_cand_ifaces wlan2 | awk 'NF{print; exit}')
_seen_if=" "
for _ifc in $_cand_ifaces wlan2; do
    case "$_ifc" in ''|*[!a-zA-Z0-9_.-]*) continue ;; esac
    case "$_seen_if" in *" $_ifc "*) continue ;; esac
    _seen_if="$_seen_if$_ifc "
    log "Cleaning TC on $_ifc..."
    if [ -f "$RUN/tc_root_owned_$_ifc" ]; then
        tc qdisc del dev "$_ifc" root 2>/dev/null
        rm -f "$RUN/tc_root_owned_$_ifc" 2>/dev/null
    elif [ -f "$RUN/tc_mq_child_$_ifc" ]; then
        # Xiaomi/ColorOS mq 根下挂载的子 HTB(parent :1 / 0:1): 不删系统 mq 根, 精确拆除 HNC 子树
        tc qdisc del dev "$_ifc" parent :1 2>/dev/null || tc qdisc del dev "$_ifc" parent 0:1 2>/dev/null || true
        rm -f "$RUN/tc_mq_child_$_ifc" 2>/dev/null
    else
        # 复用 OEM htb 1: 根的场景: 不删根, 用单次 tc filter show + awk 精准摘除实际存在的 HNC 过滤器
        tc filter show dev "$_ifc" parent 1: 2>/dev/null | awk '
            /^filter / {
                pf=""; pr=""
                for (i=1; i<NF; i++) {
                    if ($i == "pref" || $i == "prio") pf=$(i+1)
                    else if ($i == "protocol") pr=$(i+1)
                }
                if (pf ~ /^[0-9]+$/) {
                    p = pf + 0
                    if ((p >= 1 && p <= 7) || p == 50 || p == 51 || (p >= 101 && p <= 299)) {
                        k = p " " pr
                        if (!seen[k]++) print p, pr
                    }
                }
            }
        ' | while read -r _pf _pr; do
            [ -n "$_pf" ] || continue
            if [ -n "$_pr" ]; then
                tc filter del dev "$_ifc" parent 1: pref "$_pf" protocol "$_pr" 2>/dev/null \
                    || tc filter del dev "$_ifc" parent 1: pref "$_pf" 2>/dev/null || true
            else
                tc filter del dev "$_ifc" parent 1: pref "$_pf" 2>/dev/null || true
            fi
        done
        # 先拆设备子树孙子类(parent != 1:1), 再拆 1:1 下的 HNC 子类(保留 1:1 与 1:9999)
        _cls_dump=$(tc class show dev "$_ifc" 2>/dev/null)
        printf '%s\n' "$_cls_dump" | awk '
            $1=="class" && $2=="htb" {
                cid=$3; par=""
                for (i=4; i<NF; i++) if ($i == "parent") { par=$(i+1); break }
                if (cid ~ /^1:/ && cid != "1:1" && cid != "1:9999" && par != "" && par != "1:1") print cid
            }
        ' | while IFS= read -r _sc; do
            [ -n "$_sc" ] || continue
            tc qdisc del dev "$_ifc" parent "$_sc" 2>/dev/null || true
            tc class del dev "$_ifc" classid "$_sc" 2>/dev/null || true
        done
        printf '%s\n' "$_cls_dump" | awk '/class htb 1:/{print $3}' | while IFS= read -r _cid; do
            case "$_cid" in
                1:1|1:9999) continue ;;
                1:*) tc filter del dev "$_ifc" parent "$_cid" 2>/dev/null || true
                     tc qdisc del dev "$_ifc" parent "$_cid" 2>/dev/null || true
                     tc class del dev "$_ifc" classid "$_cid" 2>/dev/null || true ;;
            esac
        done
        unset _cls_dump
    fi
    if [ -x "$HNC_DIR/bin/hnc_clsact_ctl" ]; then
        "$HNC_DIR/bin/hnc_clsact_ctl" uninstall "$_ifc" >/dev/null 2>&1 && log "clsact BPF filter/map removed on $_ifc"
    fi
    # 精确移除 HNC 自装的入向过滤器(保留 AOSP clsact qdisc 与系统 tether BPF! pref 2/3 仅匹配 mirred.*ifb0 时才删)
    tc filter del dev "$_ifc" ingress pref 1 2>/dev/null || true
    tc filter del dev "$_ifc" parent ffff: pref 1 2>/dev/null || true
    for _ing_mode in ingress "parent ffff:"; do
        # shellcheck disable=SC2086
        _ing_dump=$(tc filter show dev "$_ifc" $_ing_mode 2>/dev/null)
        [ -n "$_ing_dump" ] || continue
        printf '%s\n' "$_ing_dump" | awk '
            /^filter / {
                pf=""; pr=""
                for (i=1; i<NF; i++) {
                    if ($i == "pref" || $i == "prio") pf=$(i+1)
                    else if ($i == "protocol") pr=$(i+1)
                }
                cur_pf = (pf ~ /^[0-9]+$/) ? (pf + 0) : 0
                cur_pr = pr
                if ((cur_pf >= 301 && cur_pf <= 400) || (cur_pf >= 5301 && cur_pf <= 7400) || (cur_pf >= 20001 && cur_pf <= 20100) || (cur_pf >= 25001 && cur_pf <= 27100)) {
                    want[cur_pf " " cur_pr] = 1
                }
                if ((cur_pf == 2 || cur_pf == 3) && tolower($0) ~ /mirred.*ifb0/) {
                    want[cur_pf " " cur_pr] = 1
                }
                next
            }
            cur_pf == 2 || cur_pf == 3 {
                if (tolower($0) ~ /mirred.*ifb0/) {
                    want[cur_pf " " cur_pr] = 1
                }
            }
            END {
                for (k in want) print k
            }
        ' | while read -r _ipf _ipr; do
            [ -n "$_ipf" ] || continue
            if [ -n "$_ipr" ]; then
                # shellcheck disable=SC2086
                tc filter del dev "$_ifc" $_ing_mode pref "$_ipf" protocol "$_ipr" 2>/dev/null \
                    || tc filter del dev "$_ifc" $_ing_mode pref "$_ipf" 2>/dev/null || true
            else
                # shellcheck disable=SC2086
                tc filter del dev "$_ifc" $_ing_mode pref "$_ipf" 2>/dev/null || true
            fi
        done
    done
    unset _ing_dump _ing_mode
    tc qdisc show dev "$_ifc" 2>/dev/null | grep -q "qdisc ingress ffff:" && tc qdisc del dev "$_ifc" ingress 2>/dev/null || true
done
# 若卸载/全停时热点网卡早已销毁, 兜底解绑 /sys/fs/bpf/hnc 避免内核 eBPF map 泄漏
if [ "$MODE" = "all" ] || [ "${HNC_UNINSTALL:-0}" = "1" ]; then
    rm -rf /sys/fs/bpf/hnc 2>/dev/null || true
fi
tc qdisc del dev ifb0 root 2>/dev/null
ip link set ifb0 down 2>/dev/null
ip link del ifb0 2>/dev/null
# v5.9.3 BUG-012 步骤1:上面刚把 root/ingress/ifb0 qdisc 全删了,但 cleanup.sh
# 历来不刷 run/tc_state.json —— 快照的写者只有 tc_state_snapshot.sh,而它的触发
# 全挂在 tc_manager.sh 的命令分发器上,cleanup.sh 走的是自己的 tc 删除路径。
# 结果:cleanup 之后快照仍然写着 htb_ready:true,和真实的空树完全相反,而
# bin/diag.sh 与 bin/json_health_panel.sh 只判"文件存在"就报健康。
# 这里同步刷一次(不用 tc_manager.sh 的 `( ... ) &` 异步模式):cleanup.sh 会被
# hnc_httpd 的 runBin/CombinedOutput() 调用,后台子 shell 会继承那两个管道的写端,
# 让 Wait() 一直挂着;同步跑约 50ms,cleanup 不是热路径,完全划算。
if [ -x "$HNC_DIR/bin/tc_state_snapshot.sh" ]; then
    HNC_DIR="$HNC_DIR" sh "$HNC_DIR/bin/tc_state_snapshot.sh" "$IFACE" >/dev/null 2>&1
    log "tc_state snapshot refreshed after TC cleanup (BUG-012)"
fi
log "TC cleanup done"

# ── 3. 清除 iptables 规则 ────────────────────────────────────
log "Cleaning iptables chains (v4+v6)..."
# 双栈幂等拆链(含 HNC_TUN_GUARD, HNC_ISOLATE, HNC_QUIC_APPLIM, HNC_SCALPEL 等全部子链)
_cleanup_ipt_stack() {
    _cmd="$1"
    _w="-w 2"
    if [ -z "${HNC_TEST_MODE:-}" ]; then
        "$_cmd" -w 2 -t filter -L -n >/dev/null 2>&1 || {
            "$_cmd" -t filter -L -n >/dev/null 2>&1 && _w=""
        }
    fi
    for _tc in "mangle PREROUTING  HNC_PREROUTE_GUARD" \
               "mangle PREROUTING  HNC_TUN_GUARD" \
               "mangle PREROUTING  HNC_RESTORE" \
               "mangle FORWARD     HNC_TUN_GUARD" \
               "mangle FORWARD     HNC_RESTORE" \
               "mangle FORWARD     HNC_MARK" \
               "mangle FORWARD     HNC_STATS" \
               "mangle FORWARD     HNC_TCPMSS" \
               "mangle FORWARD     HNC_APP_LIMIT" \
               "mangle FORWARD     HNC_APP_LIMIT_UP" \
               "mangle POSTROUTING HNC_APP_LIMIT_DOWN" \
               "mangle FORWARD     HNC_APP_QOS_MARK" \
               "mangle POSTROUTING HNC_APP_QOS" \
               "mangle POSTROUTING HNC_SAVE" \
               "mangle POSTROUTING HNC_EGRESS_FIX" \
               "filter FORWARD     HNC_SCALPEL" \
               "filter FORWARD     HNC_ISOLATE" \
               "filter FORWARD     HNC_CTRL" \
               "filter FORWARD     HNC_WHITELIST" \
               "filter FORWARD     HNC_QUIC" \
               "filter FORWARD     HNC_QUIC_APPLIM" \
               "filter FORWARD     HNC_CONNBLK" \
               "filter INPUT       HNC_CONNBLK_DNS" \
               "filter FORWARD     HNC_CONNBLK_DNS" \
               "filter INPUT       HNC_ENCDNS" \
               "filter FORWARD     HNC_ENCDNS" \
               "filter FORWARD     HNC_ENCDNS_STRICT" \
               "filter FORWARD     HNC_ENCDNS_DOT"; do
        set -- $_tc
        _t="$1"; _p="$2"; _h="$3"
        _n=0
        # shellcheck disable=SC2086
        while "$_cmd" $_w -t "$_t" -D "$_p" -j "$_h" 2>/dev/null; do
            _n=$((_n + 1))
            [ "$_n" -ge 32 ] && break
        done
        # shellcheck disable=SC2086
        "$_cmd" $_w -t "$_t" -F "$_h" 2>/dev/null || true
    done
    # 二级 -g 子链在父链清空后引用归零，安全清空并删除
    # shellcheck disable=SC2086
    "$_cmd" $_w -t mangle -F HNC_APP_QOS_IP 2>/dev/null || true
    # shellcheck disable=SC2086
    "$_cmd" $_w -t mangle -X HNC_APP_QOS_IP 2>/dev/null || true
    # shellcheck disable=SC2086
    for _al in $("$_cmd" $_w -t mangle -S 2>/dev/null | awk '/^-N HNC_AL_C[0-9]+$/{print $2}'); do
        [ -n "$_al" ] || continue
        # shellcheck disable=SC2086
        "$_cmd" $_w -t mangle -F "$_al" 2>/dev/null || true
        # shellcheck disable=SC2086
        "$_cmd" $_w -t mangle -X "$_al" 2>/dev/null || true
    done
    for _h in HNC_PREROUTE_GUARD HNC_TUN_GUARD HNC_RESTORE HNC_MARK HNC_STATS HNC_TCPMSS HNC_APP_LIMIT HNC_APP_LIMIT_UP HNC_APP_LIMIT_DOWN HNC_APP_QOS_MARK HNC_APP_QOS HNC_SAVE HNC_EGRESS_FIX; do
        # shellcheck disable=SC2086
        "$_cmd" $_w -t mangle -X "$_h" 2>/dev/null || true
    done
    for _h in HNC_SCALPEL HNC_ISOLATE HNC_CTRL HNC_WHITELIST HNC_QUIC HNC_QUIC_APPLIM HNC_CONNBLK HNC_CONNBLK_DNS HNC_ENCDNS HNC_ENCDNS_STRICT HNC_ENCDNS_DOT; do
        # shellcheck disable=SC2086
        "$_cmd" $_w -t filter -X "$_h" 2>/dev/null || true
    done
}
_cleanup_ipt_stack iptables
if command -v ip6tables >/dev/null 2>&1; then
    _cleanup_ipt_stack ip6tables
fi
rm -f "$HNC_DIR/run"/app_limits.*.sig "$HNC_DIR/run/app_limits_ipstats.flat" "$HNC_DIR/run/app_limits_inactive.marker" \
      "$HNC_DIR/run/app_limit.dirty" "$HNC_DIR/run/app_limit.dirty.processing" \
      "$HNC_DIR/run"/app_qos.state "$HNC_DIR/run"/app_qos.sig "$HNC_DIR/run"/app_qos.plan \
      "$HNC_DIR/run/stats_v6_map" "$HNC_DIR/run/stats_v6_retired" 2>/dev/null || true
# v5.22: WebUI 访问白名单链(INPUT 上按端口挂的跳转, 上面的 "-D INPUT -j 链" 删不掉,
# 交给脚本自己拆)。rules 模式不拆: 它是访问控制, 不是用户要清的限速规则。
if [ "$MODE" = "all" ] || [ "$MODE" = "restart" ]; then
    [ -f "$HNC_DIR/bin/webui_guard.sh" ] && sh "$HNC_DIR/bin/webui_guard.sh" remove >/dev/null 2>&1 \
        && log "webui_guard removed"
fi
# DPI v2: DNS 接管的 DNAT(nat/PREROUTING HNC_DNSTK + filter/INPUT HNC_DNSTK_IN)。
# 任何模式都拆(fail-open: 设备回到系统 DNS); httpd 仍在且配置开着时会自己补回。
[ -f "$HNC_DIR/bin/dns_takeover.sh" ] && sh "$HNC_DIR/bin/dns_takeover.sh" remove >/dev/null 2>&1 \
    && log "dns_takeover rules removed"
log "iptables cleanup done"

# ── 4. 清理临时文件（保留 data/ 目录，用户配置不删）────────
rm -f "$RUN"/*.pid "$RUN"/netevt_* "$RUN"/arp_hash "$RUN"/hotspotd.sock "$RUN"/dpid.netlink.event 2>/dev/null
rm -f "$HNC_DIR/run/hostname_cache" 2>/dev/null  # v5.33 前 shell 扫描的名字缓存(旧版残留)
rm -rf "$HNC_DIR/run/v6" 2>/dev/null              # v3.4.0：v6_sync 快照目录
# v3.5.0 P2-5: 清理(v5.33 前)device_detect.sh shell 扫描留下的临时文件
rm -f "$RUN"/scan_tmp.* "$RUN"/scan_arp.* "$RUN"/.gc_* "$RUN"/.lock_check_* 2>/dev/null
# v5.9.3 BUG-010:portal(v5.8.9 实验分支,最终未合入 main)的残留。run/ 清理是
# 白名单式逐项 rm,历来不含 portal_*,三种 mode 一个都清不掉,只有 uninstall.sh
# 的 `rm -rf run/` 会带走 —— 而日常清理和 v5.8.9-portal → v5.9.x 升级都不走那条。
# 守卫:portal 若将来真的合入 main,bin/portal_manager.sh 必然存在,那时这行绝不
# 能删会话表(用户会被强制重认证),合入时应显式删掉这几行而不是依赖守卫。
if [ ! -f "$HNC_DIR/bin/portal_manager.sh" ]; then
    rm -f "$RUN/portal_pending.json" "$RUN/portal_sessions.json" 2>/dev/null
fi
rm -rf "$RUN/json.lock" "$RUN/hnc_json.lock" "$RUN/lock" "$RUN/tc_action.lock" "$RUN"/tc_action.lock.stale.* \
       "$RUN/v6_sync.lock" "$RUN/stats_v6.lock" "$RUN/app_limits.lock" "$RUN/app_qos.lock" "$RUN/connblock.lock" 2>/dev/null
# v3.9.1: stats 临时文件 + 日期标记(stats_raw / stats_daily 是用户数据,不删)
rm -f "$RUN"/stats_map.* "$RUN"/rollup_names.* "$RUN"/rollup_agg.* "$RUN"/.s4.* "$RUN"/.s6.* "$RUN"/.sm.* \
      "$RUN"/.stats_* "$RUN"/tc_ifindex_* "$RUN/tc_restore_pending" 2>/dev/null
if [ "$MODE" = "all" ]; then
    rm -f "$RUN"/conn_blocks.* "$RUN/connblock_caps.json" "$RUN/encdns_caps.json" 2>/dev/null
fi
rm -f "$RUN"/stats_last_date 2>/dev/null
# v4.0.0-patch1.3: watchdog passive mode marker
rm -f "$RUN/watchdog_passive.marker" 2>/dev/null
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
    for c in /data/adb/modules/hotspot_net_ctl/service.sh \
             /data/adb/modules_update/hotspot_net_ctl/service.sh \
             /data/adb/modules/hotspot_network_control/service.sh \
             /data/adb/modules_update/hotspot_network_control/service.sh \
             /data/adb/hnc/service.sh; do
        if [ -z "$SERVICE_SH" ] && [ -f "$c" ]; then
            SERVICE_SH="$c"
        fi
    done
    if [ -n "$SERVICE_SH" ]; then
        log "restart: respawning $SERVICE_SH"
        nohup sh "$SERVICE_SH" </dev/null >> "$LOG" 2>&1 &
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
