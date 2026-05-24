#!/system/bin/sh
# service.sh — Magisk late_start service
# 在系统完全启动后执行,可访问所有系统服务

# v3.5.0 alpha-0:PATH 健壮性
# 强制使用系统 PATH,排除 user app(MT 管理器/termux 等)对 awk/sed/grep/tc 的劫持
# 之前的隐患:如果 user 在 root shell 中调用 service.sh,继承的 PATH 可能含 user app 路径,
# 导致 HNC 用错版本的命令(行为可能跟系统 toybox 不一致)
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

MODDIR=${0%/*}
HNC_DIR=/data/local/hnc
LOG=$HNC_DIR/logs/service.log
RUN=$HNC_DIR/run

mkdir -p $HNC_DIR/logs $RUN
# hotfix16.4: clear stale uplink degraded marker on service start; watchdog will re-probe.
rm -f $RUN/uplink_unsupported $RUN/uplink_fail_count $RUN/uplink_unsupported_logged 2>/dev/null || true
rm -rf $RUN/hnc_json.lock 2>/dev/null || true

# rc3.1 修 N-15R: 记下自己路径让 cleanup.sh restart 时能找到我们
# (KSU / SukiSU / Magisk 的 MODDIR 路径不一样, 不能硬编码)
echo "$MODDIR" > "$RUN/service.path" 2>/dev/null

# rc2 修 S8: 删除死 trap.
# 原有 trap cleanup_on_exit TERM INT + cleanup_on_exit() 函数是死代码:
# Magisk/KSU 的 post-fs-data/service 脚本是被 init 以 daemonize 方式拉起, init 不会
# 给 service.sh 发 TERM/INT (模块卸载走 uninstall.sh 钩子, 系统关机 init 发 KILL).
# 这段保留了几年没起过作用, 还给读代码的人"有清理保证"的错觉. 真清理在
# cleanup.sh 和 uninstall.sh, 不在这里.

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HNC] $1" >> $LOG
}

# rc17: keep C hotspot detector single-instance.  A manual service restart or
# watchdog race may leave two hotspotd processes; keep the pidfile target and
# remove extra instances before they both write devices.json.
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

find_live_watchdog_pid() {
    # rc30.1: match both Go binary and shell fallback
    ps -ef 2>/dev/null | awk '$0 ~ /\/data\/local\/hnc\/bin\/(hnc_watchdog|watchdog\.sh)/ && $3==1 {print $2; exit}'
}

log "=== HNC Service Starting ==="
# hotfix16.2: best-effort repair before reading rules.json in late_start.
[ -x "$HNC_DIR/bin/rules_repair.sh" ] && HNC=$HNC_DIR sh "$HNC_DIR/bin/rules_repair.sh" >> $LOG 2>&1 || true
log "Android $(getprop ro.build.version.release) / $(getprop ro.product.brand) $(getprop ro.product.model)"

# hotfix17.3: service start must refresh runtime copy from module files.
# post-fs-data may not run during manual module restart, leaving /data/local/hnc
# with an old hnc_httpd binary (observed hotfix4 backend with hotfix17 UI).
sync_runtime_from_moddir() {
    log "rc14 runtime sync: MODDIR=$MODDIR -> $HNC_DIR"

    mkdir -p "$HNC_DIR/bin" "$HNC_DIR/webroot" "$HNC_DIR/api" "$HNC_DIR/daemon/hnc_httpd" 2>/dev/null || true
    cp -rf "$MODDIR/bin/"* "$HNC_DIR/bin/" 2>/dev/null || true
    cp -rf "$MODDIR/webroot/"* "$HNC_DIR/webroot/" 2>/dev/null || true
    cp -rf "$MODDIR/api/"* "$HNC_DIR/api/" 2>/dev/null || true

    # rc14: 强制刷新运行时后端，避免旧 hnc_httpd 进程继续占用 8444。
    # 仅删除 /data/local/hnc 的运行时副本；模块目录里的正式二进制不删除。
    if [ -f "$MODDIR/daemon/hnc_httpd/hnc_httpd" ]; then
        log "runtime sync: stopping old hnc_httpd before replacing runtime binary"
        oldpid=$(cat "$RUN/httpd.pid" 2>/dev/null)
        [ -n "$oldpid" ] && kill -9 "$oldpid" 2>/dev/null || true
        if command -v pidof >/dev/null 2>&1; then
            for p in $(pidof hnc_httpd 2>/dev/null); do
                [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
            done
        fi
        rm -f "$RUN/httpd.pid" "$RUN/httpd_bind_ip" 2>/dev/null || true
        rm -f "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true

        cp -f "$MODDIR/daemon/hnc_httpd/hnc_httpd" "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        chmod 755 "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true

        if command -v strings >/dev/null 2>&1; then
            if strings "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null | grep -q '/api/dpi_state' \
               && strings "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null | grep -q '/api/dpi_probe'; then
                log "runtime sync: hnc_httpd refreshed with DPI API routes"
            else
                log "ERROR: refreshed hnc_httpd is missing /api/dpi_state or /api/dpi_probe"
            fi
        else
            log "runtime sync: strings not available; skipped DPI API route check"
        fi
    else
        log "runtime sync WARN: module hnc_httpd missing at $MODDIR/daemon/hnc_httpd/hnc_httpd"
    fi

    chmod 755 "$HNC_DIR/bin/"*.sh 2>/dev/null || true
    # rc30.11: sync_runtime_from_moddir 把模块 bin/ 拷到 /data/local/hnc/bin/ 后,
    # 立即 chmod + chcon 兜底. 不能依赖 post-fs-data.sh — 它跑时这步还没发生.
    # chcon system_file:s0: 防止 cp 把 context 改成 system_data_file:s0, 后者
    # 在 ColorOS 16 / SukiSU 上让 Go fork+exec 报 EPERM (真机 RMX5010 实测).
    for _b in hotspotd hnc_ipc hnc_tc_ingress mdns_resolve hnc_json hnc_dpid \
              hnc_dpid_supervisor hnc_watchdog \
              hnc_launcher fork_probe \
              hnc_ndpi_probe ndpiReader hnc_dpid_ndpi; do
        if [ -f "$HNC_DIR/bin/$_b" ]; then
            chmod 755 "$HNC_DIR/bin/$_b" 2>/dev/null || true
            chcon u:object_r:system_file:s0 "$HNC_DIR/bin/$_b" 2>/dev/null || true
        fi
    done
    # hnc_httpd 单独
    if [ -f "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" ]; then
        chmod 755 "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        chcon u:object_r:system_file:s0 "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
    fi
}

sync_runtime_from_moddir
# hotfix13: record platform/kernel capability profile for diagnostics and UI fallback hints
if [ -x $HNC_DIR/bin/capability_probe.sh ]; then
    ( sh $HNC_DIR/bin/capability_probe.sh >> $HNC_DIR/logs/capabilities.log 2>&1 ) &
fi

# v5.5.0: AHNC → HNC migration (idempotent, runs once via marker file)
if [ -x $HNC_DIR/bin/ahnc_migration.sh ]; then
    ( sh $HNC_DIR/bin/ahnc_migration.sh >> $HNC_DIR/logs/migration.log 2>&1 ) &
fi

# 等待系统网络服务就绪
wait_for_network() {
    local max=60
    local cnt=0
    while [ $cnt -lt $max ]; do
        # 检查 wlan0 或热点接口
        if ip link show 2>/dev/null | grep -qE 'wlan|ap0|swlan'; then
            log "Network interface ready"
            return 0
        fi
        sleep 2
        cnt=$((cnt+2))
    done
    log "WARN: Network wait timeout, continuing anyway"
    return 1
}

# 等待 bootcomplete
wait_boot_complete() {
    local cnt=0
    while [ "$(getprop sys.boot_completed)" != "1" ] && [ $cnt -lt 120 ]; do
        sleep 2
        cnt=$((cnt+2))
    done
    log "Boot completed at ${cnt}s"
}

wait_boot_complete
wait_for_network

# ─── v4.0.0-patch1.5 Defer Init(延迟初始化)────────────────────
# 历史(v4.0.0-patch1.4 及更早):
#   service.sh 跑在 late_start(~boot 5s), 此时热点通常还没起,
#   detect_hotspot_iface 的探测链层层失败最终兜底 echo "wlan0",
#   然后 tc_manager.sh init wlan0 + iptables_manager.sh init
#   直接把 HTB 队列和 MARK 规则挂到了本机 WiFi 接口 wlan0,
#   污染手机自己的上网体验(用户真机事故: 感觉"上网慢",
#   tc qdisc show dev wlan0 发现 HTB 活着几个月,但无人察觉)。
#
# v4.0.0-patch1.5 修正:
#   service.sh 彻底剥离业务初始化,不再探测 iface / 不再 init tc /
#   不再 init iptables / 不再直接拉 httpd。只做三件事:
#     1. 建目录 / 初始化 data 文件(已有逻辑,不变)
#     2. 启动 device_detect daemon
#     3. 启动 watchdog(它是唯一的状态机,负责探测 + init + 拉 httpd)
#   如果 remote_enabled=true, 写 httpd.wanted marker, watchdog 探到热点
#   就绪后自己拉 httpd。service.sh 绝不碰 wlan0。

log "v4.0.0-patch1.5 Defer Init: iface detection + tc/iptables init delegated to watchdog"

# v5.0: httpd 永远启动 (至少 loopback), 本机 WebUI 依赖它
# REMOTE_ENABLED 只决定是否同时开热点段 HTTPS
REMOTE_ENABLED=$(grep -o '"remote_enabled"[[:space:]]*:[[:space:]]*[a-z]*' \
    $HNC_DIR/data/rules.json 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')
if [ "$REMOTE_ENABLED" = "true" ]; then
    log "remote_enabled=true, httpd.wanted marker set (watchdog will launch httpd with remote+loopback when hotspot ready)"
else
    log "remote_enabled=false, httpd loopback-only mode (本机 WebUI 仍可用)"
fi
# marker 总是 set — watchdog 看 remote_enabled 再决定是否带 -bind
touch "$RUN/httpd.wanted" 2>/dev/null

# ─── rc30.12.18: auth_required 自动迁移到默认拒绝 ────────────────
# rc30.12.18 起 hnc_httpd 改成"默认拒绝"鉴权 (isPublicPath 白名单 + 其他都要 cookie).
# 老 rules.json 默认 auth_required=false (rc25 时代的兼容设置), 升级到 rc30.12.18
# 后这个值不再有"放行匿名"的语义 — 不管 true/false, 非公共路径都强制 cookie.
#
# 但为了让用户/WebUI 配置 toggle 看起来一致 (不让用户看到 toggle=OFF 但实际全要登录),
# 自动把它修正成 true.
#
# 这个改动是单向的: 一旦升级到 rc30.12.18+, auth_required 永远是 true.
# 如果有人后续手动改回 false, 后端也会忽略它 (只 log warn).
RULES_JSON="$HNC_DIR/data/rules.json"
if [ -f "$RULES_JSON" ]; then
    CUR_AUTH=$(grep -o '"auth_required"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$RULES_JSON" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')
    if [ "$CUR_AUTH" = "false" ]; then
        log "rc30.12.18 migration: auth_required=false in rules.json detected, auto-upgrading to true"
        log "  (rc30.12.18 enforces default-deny regardless; this just keeps WebUI toggle consistent)"
        # 简单 sed 替换 (rules.json 里只可能有一个 auth_required 字段)
        sed -i 's/"auth_required"[[:space:]]*:[[:space:]]*false/"auth_required": true/' "$RULES_JSON" 2>/dev/null
        # 失败也无妨 - 后端反正不看这字段了, 只是 cosmetic
    fi
fi

# 验证 hnc_httpd binary 存在且可执行(防御性 chmod,zip 安装可能丢 +x)
HTTPD_BIN="$HNC_DIR/daemon/hnc_httpd/hnc_httpd"
if [ -f "$HTTPD_BIN" ] && [ ! -x "$HTTPD_BIN" ]; then
    chmod 755 "$HTTPD_BIN" 2>/dev/null
    log "fixed +x on $HTTPD_BIN"
fi
if [ ! -x "$HTTPD_BIN" ]; then
    log "WARN: $HTTPD_BIN missing or not executable — WebUI 将不可用"
    log "      check that post-fs-data.sh copied daemon/hnc_httpd/hnc_httpd"
fi

# ─── rc30.12.14: 生成本机管理员密钥 (loopback 鉴权加固) ───────────
# 用途: 防止本机任意低信任 App 直接调用 loopback 管理面.
# WebUI 通过 ksu.exec 读这个文件, 注入 X-HNC-Local-Admin header.
# 普通 App 无 root, 读不到 mode 0600 owner root 的文件 → 无法构造 valid header.
LOCAL_ADMIN_SECRET="$RUN/local_admin.secret"
if [ ! -s "$LOCAL_ADMIN_SECRET" ]; then
    # 32 字节随机, hex 编码. /dev/urandom 失败时退到 date+random 兜底
    if [ -r /dev/urandom ]; then
        SECRET_VAL=$(head -c 32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' 2>/dev/null)
    fi
    if [ -z "$SECRET_VAL" ]; then
        SECRET_VAL=$(echo "$(date +%s%N)$$$RANDOM$RANDOM" | sha256sum 2>/dev/null | awk '{print $1}')
    fi
    if [ -n "$SECRET_VAL" ]; then
        # rc30.12.16 P2-1: umask 改用子 shell 隔离, 避免污染后续脚本.
        # 之前 `umask 077` 后没恢复, 后续 `>` 创建的文件都会被收紧权限.
        ( umask 077; printf "%s" "$SECRET_VAL" > "$LOCAL_ADMIN_SECRET" )
        chmod 600 "$LOCAL_ADMIN_SECRET" 2>/dev/null
        chown root:root "$LOCAL_ADMIN_SECRET" 2>/dev/null
        log "rc30.12.14: generated local admin secret ($LOCAL_ADMIN_SECRET, mode 0600)"
    else
        log "rc30.12.14: WARN failed to generate local_admin.secret (falling back to legacy loopback bypass)"
    fi
fi

# ─── 启动设备检测守护进程（v3.0.0：优先 C daemon hotspotd）─
# device_detect.sh daemon 内部会优先尝试启动 hotspotd(C)；
# 若二进制不存在则自动回落到原 shell 轮询（向下兼容）
#
# v3.5.2 P0-A 修复:detect.pid 和 hotspotd.pid 不再存同一个 PID。
# - C daemon 成功接管时,只有 hotspotd.pid 有值,detect.pid 不写
# - shell fallback 时,只有 detect.pid 有值(device_detect.sh 自己写)
# - watchdog 优先检查 hotspotd.pid,存在时跳过 detect.pid 检查
# 根本原因:之前两个 pid 指同一 PID,hotspotd 崩掉后 watchdog 两个
# if 都触发重启,导致 hotspotd C daemon 和 shell fallback 同时运行,
# 并发写 devices.json.tmp → JSON 损坏(review P0-A)
log "Starting device detector (C daemon preferred)..."
sh $HNC_DIR/bin/device_detect.sh daemon >> $HNC_DIR/logs/detect.log 2>&1 &
DETECT_SHELL_PID=$!
# hotfix10 S11: 固定 sleep 2 在慢启动上会误判 shell fallback。
# 最多等 5s,每 100ms poll 一次 hotspotd.pid。
HPID=""
i=0
while [ $i -lt 50 ]; do
    HPID=$(cat $RUN/hotspotd.pid 2>/dev/null)
    [ -n "$HPID" ] && kill -0 "$HPID" 2>/dev/null && break
    if usleep 100000 2>/dev/null; then
        i=$((i + 1))
    else
        sleep 1
        i=$((i + 10))
    fi
done
# 检查 C daemon 是否接管了（hotspotd.pid 存在且进程活着）
if [ -n "$HPID" ] && kill -0 "$HPID" 2>/dev/null; then
    log "C daemon hotspotd running (PID=$HPID)"
    # v3.5.2 P0-A:不再 echo $HPID > detect.pid。
    # C daemon 模式下 detect.pid 应当不存在,让 watchdog 看到"没 detect 需要照料"
    rm -f "$RUN/detect.pid" 2>/dev/null
else
    # shell fallback 在 daemon_shell_fallback 里自己写了 detect.pid
    log "Shell daemon fallback running (PID=$DETECT_SHELL_PID)"
fi
prune_duplicate_hotspotd

# ─── rc30.12: shell pre-launch hnc_httpd ─────────────────────
# 跟 rc30.11 区别: 不再 pre-launch supervisor (C launcher 替代了那个角色,
# 在下面 DPID launcher 块里启动). 只 pre-launch httpd, 因为 httpd 需要
# 在 watchdog 起来之前就 ready, 不然 watchdog 检测到 httpd 不在会尝试
# fork (在 ColorOS 16 上失败).

# rc30.12.16 P0-1 修复: 之前 pre-launch + sentinel 两处硬编码 -bind 0.0.0.0,
# 完全无视 REMOTE_ENABLED. 现在统一通过 launch_httpd_safe 函数, 读 remote_enabled
# 决定是否暴露热点段 HTTPS. remote_enabled=false 时只开 loopback (本机 WebUI).
#
# rc30.12.19 P2 加固: 上一版用 $REMOTE_ENABLED 全局快照, 用户中途改 remote_enabled=false
# 之后, 如果 httpd 恰好死掉, sentinel 会用旧快照拉起 0.0.0.0 模式, 30s 窗口内会
# 跟用户配置不一致. 现在改成每次调用都从 rules.json 实时读, 关闭这个窗口.
launch_httpd_safe() {
    # 每次调用都重新读 rules.json (GPT 二审 P2 修复)
    _remote_now=$(grep -o '"remote_enabled"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$HNC_DIR/data/rules.json" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')
    if [ "$_remote_now" = "true" ]; then
        nohup "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" \
            -bind 0.0.0.0 -port 8443 -loopback-port 8444 \
            -hnc-dir "$HNC_DIR" -http-port 8080 \
            >> "$HNC_DIR/logs/httpd.log" 2>&1 &
        echo $! > "$RUN/httpd.pid" 2>/dev/null || true
        log "rc30.12.19 launch_httpd_safe: remote+loopback mode (PID=$!, remote_enabled=true)"
    else
        nohup "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" \
            -loopback-port 8444 \
            -hnc-dir "$HNC_DIR" \
            >> "$HNC_DIR/logs/httpd.log" 2>&1 &
        echo $! > "$RUN/httpd.pid" 2>/dev/null || true
        log "rc30.12.19 launch_httpd_safe: loopback-only mode (PID=$!, remote_enabled=$_remote_now)"
    fi
    unset _remote_now
}

if [ -x "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" ]; then
    HP=$(ps -ef 2>/dev/null | grep '/data/local/hnc/daemon/hnc_httpd/hnc_httpd' \
         | grep -v grep | awk '{print $2}' | head -1)
    if [ -n "$HP" ] && kill -0 "$HP" 2>/dev/null; then
        log "rc30.12 pre-launch: hnc_httpd already running (PID=$HP)"
    else
        launch_httpd_safe
        sleep 1
    fi
fi

# ─── 启动 Watchdog ──────────────────────────────────────────
log "Starting watchdog..."
WPID=$(cat "$RUN/watchdog.pid" 2>/dev/null)
if [ -n "$WPID" ] && kill -0 "$WPID" 2>/dev/null; then
    log "watchdog already running (PID=$WPID), skip duplicate launch"
else
    LIVE_WD=$(find_live_watchdog_pid)
    if [ -n "$LIVE_WD" ] && kill -0 "$LIVE_WD" 2>/dev/null; then
        echo "$LIVE_WD" > "$RUN/watchdog.pid" 2>/dev/null || true
        log "watchdog live without pidfile (PID=$LIVE_WD), repaired pidfile"
    else
        rm -f "$RUN/watchdog.pid" 2>/dev/null || true
        # rc30.1: prefer Go hnc_watchdog binary over the shell main loop.
        # The Go binary uses watchdog.sh in "action" mode for business logic
        # but runs the supervision loop itself, immune to PATH/namespace
        # issues that wedged the shell loop in post-fs-data context.
        if [ -x "$HNC_DIR/bin/hnc_watchdog" ]; then
            nohup "$HNC_DIR/bin/hnc_watchdog" >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid"
            log "watchdog (Go, rc30.1+) started (PID=$(cat $RUN/watchdog.pid 2>/dev/null))"
        else
            sh "$HNC_DIR/bin/watchdog.sh" >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid"
            log "watchdog (shell fallback) started (PID=$(cat $RUN/watchdog.pid 2>/dev/null))"
        fi
    fi
fi

# hotfix10: 启动后延迟清理一次长期未见的离线规则,防止 rules.json 膨胀。
if [ -x "$HNC_DIR/bin/cleanup_stale_rules.sh" ]; then
    (sleep 60 && sh "$HNC_DIR/bin/cleanup_stale_rules.sh") >> "$HNC_DIR/logs/cleanup_stale.log" 2>&1 &
fi

log "=== All services started ==="
log "All services started. WebUI: open KernelSU manager → modules → HNC"

# ─── v5.0 alpha.2: Offload Recovery ────────────────────────
# hotspotd 重启后 scheduler 内存里 limited 集合是空的, 但 rules.json 里
# 可能有 limit_enabled=true 的设备. 重新通知 scheduler 建立集合,
# 这样下一次 apply_device_rule.sh 或 watchdog 触发时状态一致.
#
# 后台异步跑, 不阻塞 service.sh. hotspotd 刚启动需要 2s 让 unix socket 就绪.
(
    sleep 3
    RULES="$HNC_DIR/data/rules.json"
    HNC_IPC="$HNC_DIR/bin/hnc_ipc"
    [ -f "$RULES" ] && [ -x "$HNC_IPC" ] || exit 0

    # 扫 rules.json 里所有 "limit_enabled":true 的 mac
    # 格式假设: {"aa:bb:...":{..."limit_enabled":true...},...}
    # 用 grep 非贪婪粗暴匹配, 不引入 jq 依赖 (ColorOS 不装)
    RECOVERED=0
    for MAC in $(grep -oE '"[0-9a-fA-F:]{17}"[^}]*"limit_enabled"[[:space:]]*:[[:space:]]*true' "$RULES" \
                 | grep -oE '^"[0-9a-fA-F:]{17}"' \
                 | tr -d '"'); do
        "$HNC_IPC" OFFLOAD_NOTIFY_LIMIT "$MAC" 1 >/dev/null 2>&1 && RECOVERED=$((RECOVERED+1))
    done
    if [ "$RECOVERED" -gt 0 ]; then
        log "offload recovery: notified $RECOVERED limited device(s) to scheduler"
    fi
) &

# rc30.12.16 P0-2: sentinel 块已移到 DPID launcher 选择逻辑之后,
# 避免后台 subshell 启动时 $DPID_LAUNCHER 还是空字符串.

# ─── 热点自动启动 ────────────────────────────────────────────
# 读取 rules.json 里的 hotspot_auto 字段（WebUI 控制）
HOTSPOT_AUTO=$(grep -o '"hotspot_auto"[[:space:]]*:[[:space:]]*[a-z]*' \
    $HNC_DIR/data/rules.json 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')

if [ "$HOTSPOT_AUTO" = "true" ]; then
    log "hotspot_auto=true, launching hotspot_autostart.sh in background..."
    # 延迟 5 秒再启动，确保其他网络服务就绪
    (sleep 5 && sh $HNC_DIR/bin/hotspot_autostart.sh start) \
        >> $HNC_DIR/logs/hotspot.log 2>&1 &
    echo $! > $RUN/hotspot.pid
    log "Hotspot autostart scheduled (PID: $(cat $RUN/hotspot.pid))"
else
    log "hotspot_auto=false, skipping autostart"
fi

# ─── hnc_dpid (DPI 被动观察 daemon, v5.3.0-rc12 新增) ────────────
# hnc_dpid 是被动元数据捕获 daemon: AF_PACKET socket + cBPF filter 抓
# DNS (53) 和 TLS ClientHello (443), 解析 SNI/ALPN/DNS query name,
# 输出 dpi_state.json 给 WebUI 消费.
#
# 不做任何主动操作: 不 NFQUEUE 不 DNS 劫持 不改 iptables/tc.
# 故意设计成 0 副作用 — 即使它崩了也只影响 WebUI 的 DPI 页面.
#
# disable_capture=true 时它进 disabled 模式不抓包, 仅写空 state.
# AF_PACKET 不可用或没探到热点接口时进 blind 模式.
# 进程 60s 内崩 3 次进 crash_loop 模式 — daemon 不再自动重启,
# 留 dpi_state.json mode=crash_loop, 用户手动清 crashflag 才恢复.
DPID_BIN="$HNC_DIR/bin/hnc_dpid"
DPID_GUARD="$HNC_DIR/bin/hnc_dpid_guard.sh"
# rc30.0: Go supervisor replacing the shell guard. Static binary, no
# dependency on /system/bin/* tools, immune to post-fs-data namespace
# transitions that wedged hnc_dpid_guard.sh in rc29.x.
# rc30.12: Go supervisor 在 ColorOS 16 / SukiSU 内部 fork+exec 被某条
# 内核策略拦下报 EPERM (验证: C fork+execv 同一环境 100% 工作, 但 Go
# runtime 用 CLONE_VM|CLONE_VFORK 路径被挡). 故 rc30.12 引入 C launcher
# 替代 Go supervisor, 优先级翻转: C > shell > Go.
DPID_SUPERVISOR="$HNC_DIR/bin/hnc_dpid_supervisor"
DPID_LAUNCHER_C="$HNC_DIR/bin/hnc_launcher"
FORK_PROBE="$HNC_DIR/bin/fork_probe"
DPID_LAUNCHER="$DPID_BIN"
DPID_CONFIG="$HNC_DIR/etc/dpi_config.json"
DPID_PID="$RUN/dpid.pid"
DPID_GUARD_PID="$RUN/dpid_guard.pid"

find_live_dpid_guard_pid() {
    # rc30.0: also match supervisor binary name (replaces shell guard).
    # rc30.12: also match C launcher.
    ps -ef 2>/dev/null | grep -E '[h]nc_launcher|[h]nc_dpid_supervisor|[h]nc_dpid_guard\.sh' \
        | awk 'NR==1{print $2}'
}

# rc30.12 launcher priority + auto-probe:
#   1. hnc_launcher (C binary, optimal)         — needs probe to confirm fork+execv works
#   2. hnc_dpid_guard.sh (shell, universally compatible)
#   3. hnc_dpid_supervisor (Go, may EPERM on hardened ROMs)
#   4. hnc_dpid (direct, last resort)
#
# Probe 逻辑: 用 fork_probe 测一下 C fork+execv 能不能跑.
# 能跑 → C launcher 优雅路径
# 不能跑 → shell guard 兼容路径 (rc29.x 稳定多年)
# 都没有 → Go supervisor 兜底 (实测不行, 但保留代码以防有人需要)
LAUNCHER_CHOICE=""
if [ -x "$DPID_LAUNCHER_C" ] && [ -x "$FORK_PROBE" ]; then
    # 用 /system/bin/true 测试 (它执行后立刻退 0)
    if "$FORK_PROBE" /system/bin/true >/dev/null 2>&1; then
        # rc30.12.28 加固: fork_probe PASS 不代表 hnc_launcher 自己能 exec.
        # 老的 hnc_launcher 在 Bionic 上可能因为 TLS segment 对齐错 (8 vs 64) 直接 abort,
        # 这跟 fork+execv 能力无关. 真试一下 hnc_launcher --version (或 -h), 看是不是
        # exit 0/正常错误码. 立刻 abort (137/134) 就说明二进制损坏, 跳过.
        _launcher_test=$("$DPID_LAUNCHER_C" --version 2>&1)
        _launcher_test_rc=$?
        # abort: SIGABRT 6 → exit 134 (128+6) or 蓝端报错文字 "Aborted" / "underaligned"
        if echo "$_launcher_test" | grep -qE 'underaligned|Aborted|cannot execute|error:.*executable'; then
            log "dpid launcher: hnc_launcher binary broken (TLS/Bionic mismatch), skip"
            log "  diag: $(echo "$_launcher_test" | head -1)"
        elif [ "$_launcher_test_rc" = "134" ] || [ "$_launcher_test_rc" = "137" ]; then
            log "dpid launcher: hnc_launcher aborted (rc=$_launcher_test_rc), skip"
        else
            DPID_LAUNCHER="$DPID_LAUNCHER_C"
            LAUNCHER_CHOICE="c_launcher"
            log "dpid launcher: hnc_launcher (C, rc30.12+) — fork_probe PASS + exec PASS"
        fi
        unset _launcher_test _launcher_test_rc
    else
        log "dpid launcher: fork_probe FAIL on this device, falling back to shell guard"
    fi
fi

if [ -z "$LAUNCHER_CHOICE" ] && [ -x "$DPID_GUARD" ]; then
    DPID_LAUNCHER="$DPID_GUARD"
    LAUNCHER_CHOICE="shell_guard"
    log "dpid launcher: hnc_dpid_guard.sh (shell, universal fallback)"
fi

if [ -z "$LAUNCHER_CHOICE" ] && [ -x "$DPID_SUPERVISOR" ]; then
    DPID_LAUNCHER="$DPID_SUPERVISOR"
    LAUNCHER_CHOICE="go_supervisor"
    log "dpid launcher: hnc_dpid_supervisor (Go, last-resort) — may fail on hardened ROMs"
fi


if [ ! -x "$DPID_BIN" ]; then
    log "WARN: hnc_dpid binary missing at $DPID_BIN, DPI 功能不可用"
else
    # 软迁: 把模块内默认 dpi_config.json 复制到 etc/ (如果用户没有自定义)
    mkdir -p "$HNC_DIR/etc" 2>/dev/null || true
    if [ ! -f "$DPID_CONFIG" ] && [ -f "$MODDIR/data/dpi_config.json" ]; then
        cp -f "$MODDIR/data/dpi_config.json" "$DPID_CONFIG" 2>/dev/null
        chmod 644 "$DPID_CONFIG" 2>/dev/null
        log "dpid: installed default dpi_config.json to $DPID_CONFIG"
    fi
    # rc20.1: install default DPI L3 rules once. Users can later import/update
    # /data/local/hnc/etc/dpi_rules.json without reflashing the module.
    # rc29.3: also enforce version upgrade. The old `[ ! -f ]` guard meant
    # users who installed rc28.1.1 / rc29.0 / rc29.1 already had a stale
    # dpi_rules.json that never got refreshed even when newer rc shipped a
    # much more complete one. Concrete user-visible bug: douyinvod.com and
    # douyincdn.com (抖音 video CDN) weren't matched by the stale rules, so
    # 抖音 traffic was falling through to bytedance_group fallback ("字节系
    # 服务") instead of being recognized as "抖音 / video".
    DPID_RULES="$HNC_DIR/etc/dpi_rules.json"
    MOD_RULES="$MODDIR/data/dpi_rules.json"
    if [ ! -f "$DPID_RULES" ] && [ -f "$MOD_RULES" ]; then
        cp -f "$MOD_RULES" "$DPID_RULES" 2>/dev/null
        chmod 644 "$DPID_RULES" 2>/dev/null
        log "dpid: installed default dpi_rules.json to $DPID_RULES"
    elif [ -f "$DPID_RULES" ] && [ -f "$MOD_RULES" ]; then
        # rc29.3 upgrade path: compare rules_version. If module ships a different
        # (presumably newer) version, back up the user's current file and replace.
        MOD_VER=$(grep -m1 'rules_version' "$MOD_RULES" 2>/dev/null | sed 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        ETC_VER=$(grep -m1 'rules_version' "$DPID_RULES" 2>/dev/null | sed 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$MOD_VER" ] && [ "$MOD_VER" != "$ETC_VER" ]; then
            BAK="$DPID_RULES.bak-$(date +%s 2>/dev/null || echo prev)"
            mv "$DPID_RULES" "$BAK" 2>/dev/null
            cp -f "$MOD_RULES" "$DPID_RULES" 2>/dev/null
            chmod 644 "$DPID_RULES" 2>/dev/null
            log "dpid: upgraded dpi_rules.json: was [$ETC_VER] -> now [$MOD_VER]; user backup at $BAK"
        fi
    fi

    # rc30.12.31 (TASK-a Stage 2): sync dpi_rules.d/ subset directory if the
    # module ships one. dpid prefers etc/dpi_rules.d/*.json (globbed + merged)
    # over the legacy single etc/dpi_rules.json.
    # rc30.12.32 (TASK-a Stage 3): module now ships data/dpi_rules.d/ (23 bucket
    # files, generated by `tools/dpi_rules_split.py split` from dpi_rules.json).
    # dpi_rules.json itself is now a derived product (generated by
    # `tools/dpi_rules_split.py sync-legacy` from the bucket files), kept as a
    # 70KB safety net for fallback. This block is no longer dormant — first
    # rc since rc30.12.30 where dpid actually goes through loadL3RulesFromDir.
    #
    # Sync strategy: rm -rf the destination then cp -r the source. We don't
    # try to merge user edits in /data/local/hnc/etc/dpi_rules.d/ because
    # user-authored subsets belong in 99-user-custom.json, which the module
    # never ships (so it survives this sync). If the user has rolled their
    # own non-99 subset they'll lose it on upgrade — same trade-off as the
    # legacy dpi_rules.json upgrade path above.
    MOD_RULES_D="$MODDIR/data/dpi_rules.d"
    DPID_RULES_D="$HNC_DIR/etc/dpi_rules.d"
    if [ -d "$MOD_RULES_D" ]; then
        # Preserve 99-user-custom.json across the resync if it exists.
        USER_CUSTOM_TMP=""
        if [ -f "$DPID_RULES_D/99-user-custom.json" ]; then
            USER_CUSTOM_TMP="$HNC_DIR/etc/.99-user-custom.json.preserve.$$"
            cp -f "$DPID_RULES_D/99-user-custom.json" "$USER_CUSTOM_TMP" 2>/dev/null
        fi
        rm -rf "$DPID_RULES_D" 2>/dev/null
        cp -r "$MOD_RULES_D" "$DPID_RULES_D" 2>/dev/null
        chmod 755 "$DPID_RULES_D" 2>/dev/null
        find "$DPID_RULES_D" -type f -name '*.json' -exec chmod 644 {} \; 2>/dev/null
        if [ -n "$USER_CUSTOM_TMP" ] && [ -f "$USER_CUSTOM_TMP" ]; then
            mv "$USER_CUSTOM_TMP" "$DPID_RULES_D/99-user-custom.json" 2>/dev/null
            chmod 644 "$DPID_RULES_D/99-user-custom.json" 2>/dev/null
        fi
        log "dpid: synced dpi_rules.d/ ($(find "$DPID_RULES_D" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l) subset files) to $DPID_RULES_D"
    fi

    # v5.6.0-rc2: auto-expand blocklist. Soft-install — if the user has
    # already edited /data/local/hnc/etc/auto_expand_blocklist.json, respect
    # it; otherwise drop in the seed list shipped with the module. The
    # auto-expander reads this on every tick, so edits take effect within
    # ~60s without restarting dpid.
    DPID_BLOCKLIST="$HNC_DIR/etc/auto_expand_blocklist.json"
    if [ ! -f "$DPID_BLOCKLIST" ] && [ -f "$MODDIR/data/auto_expand_blocklist.json" ]; then
        cp -f "$MODDIR/data/auto_expand_blocklist.json" "$DPID_BLOCKLIST" 2>/dev/null
        chmod 644 "$DPID_BLOCKLIST" 2>/dev/null
        log "dpid: installed default auto_expand_blocklist.json to $DPID_BLOCKLIST"
    fi

    # v5.7.0-rc3: curated entity library (self-authored, license-clean) used by
    # the candidate flywheel to recognize shared infrastructure (CDN / cloud /
    # analytics / push SDK) on first sighting. Soft-install; on a module version
    # bump, back up the user's copy and refresh so the curated lib grows across
    # updates (same trade-off as dpi_rules.json above).
    DPID_ENTITY="$HNC_DIR/etc/entity_db.json"
    MOD_ENTITY="$MODDIR/data/entity_db.json"
    if [ ! -f "$DPID_ENTITY" ] && [ -f "$MOD_ENTITY" ]; then
        cp -f "$MOD_ENTITY" "$DPID_ENTITY" 2>/dev/null
        chmod 644 "$DPID_ENTITY" 2>/dev/null
        log "dpid: installed default entity_db.json to $DPID_ENTITY"
    elif [ -f "$DPID_ENTITY" ] && [ -f "$MOD_ENTITY" ]; then
        MOD_EV=$(grep -m1 '"version"' "$MOD_ENTITY" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        ETC_EV=$(grep -m1 '"version"' "$DPID_ENTITY" 2>/dev/null | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$MOD_EV" ] && [ "$MOD_EV" != "$ETC_EV" ]; then
            BAK="$DPID_ENTITY.bak-$(date +%s 2>/dev/null || echo prev)"
            mv "$DPID_ENTITY" "$BAK" 2>/dev/null
            cp -f "$MOD_ENTITY" "$DPID_ENTITY" 2>/dev/null
            chmod 644 "$DPID_ENTITY" 2>/dev/null
            log "dpid: upgraded entity_db.json: was [$ETC_EV] -> now [$MOD_EV]; user backup at $BAK"
        fi
    fi

    # rc22 (DFP): install default JA4 fingerprint library. Same soft-migration:
    # if user already has /data/local/hnc/etc/dpi_ja4_fingerprints.json we
    # respect it; otherwise drop the seed library shipped with the module.
    DPID_JA4="$HNC_DIR/etc/dpi_ja4_fingerprints.json"
    if [ ! -f "$DPID_JA4" ] && [ -f "$MODDIR/data/dpi_ja4_fingerprints.json" ]; then
        cp -f "$MODDIR/data/dpi_ja4_fingerprints.json" "$DPID_JA4" 2>/dev/null
        chmod 644 "$DPID_JA4" 2>/dev/null
        log "dpid: installed default dpi_ja4_fingerprints.json to $DPID_JA4"
    fi

    # rc24.1: optional nDPI-lab bridge config and one-shot sample. Disabled by default;
    # this repack bundles an Android arm64 hnc_ndpi_probe for availability tests.
    DPID_NDPI_CONF="$HNC_DIR/etc/dpi_ndpi_config.json"
    if [ ! -f "$DPID_NDPI_CONF" ] && [ -f "$MODDIR/data/dpi_ndpi_config.json" ]; then
        cp -f "$MODDIR/data/dpi_ndpi_config.json" "$DPID_NDPI_CONF" 2>/dev/null
        chmod 644 "$DPID_NDPI_CONF" 2>/dev/null || true
        log "dpid: installed default dpi_ndpi_config.json to $DPID_NDPI_CONF"
    fi

    # rc14: 优先启动 dpid guard / supervisor, 并用独立 dpid_guard.pid 防重复.
    # dpid.pid 只给真实 hnc_dpid child 使用, 避免 guard/child 互相覆盖 pidfile.
    # rc30.0: 同一启动块同时适用 Go supervisor (DPID_SUPERVISOR) 和老 shell guard
    # (DPID_GUARD). 二者都自维护 dpid_guard.pid 锁文件, 启动方式一致 (nohup &).
    # rc30.12.28 修 P0 (GPT 三审): 之前判断只匹配 SUPERVISOR/GUARD, C launcher 选中后
    # 会落到 else 分支直启 hnc_dpid. 后续 sentinel 又会拉 C launcher, 双 dpid 风险.
    # 现在改成: 任何 launcher (C/shell/Go) 都走统一 launcher 分支, 只有 fallback 到
    # DPID_BIN (没有 launcher 可用) 才走 direct 模式.
    if [ "$DPID_LAUNCHER" != "$DPID_BIN" ]; then
        gp=$(cat "$DPID_GUARD_PID" 2>/dev/null)
        if [ -n "$gp" ] && kill -0 "$gp" 2>/dev/null; then
            log "hnc_dpid launcher already running (PID=$gp, choice=$LAUNCHER_CHOICE), skip duplicate launch"
        else
            live_gp=$(find_live_dpid_guard_pid)
            if [ -n "$live_gp" ] && kill -0 "$live_gp" 2>/dev/null; then
                echo "$live_gp" > "$DPID_GUARD_PID" 2>/dev/null || true
                log "hnc_dpid launcher live without pidfile (PID=$live_gp, choice=$LAUNCHER_CHOICE), repaired pidfile and skipped duplicate launch"
            else
                rm -f "$DPID_GUARD_PID" 2>/dev/null || true
                log "starting hnc_dpid launcher: $DPID_LAUNCHER (choice=$LAUNCHER_CHOICE)"
                nohup "$DPID_LAUNCHER" >> "$HNC_DIR/logs/dpid_guard.log" 2>&1 &
                echo $! > "$DPID_GUARD_PID"
                log "hnc_dpid launcher started (PID: $(cat $DPID_GUARD_PID))"
            fi
        fi
    else
        dp=$(cat "$DPID_PID" 2>/dev/null)
        if [ -n "$dp" ] && kill -0 "$dp" 2>/dev/null; then
            log "hnc_dpid already running (PID=$dp, direct mode), skip duplicate launch"
        else
            log "starting hnc_dpid direct: $DPID_BIN (no launcher available)"
            nohup "$DPID_BIN" -config "$DPID_CONFIG" >> "$HNC_DIR/logs/dpid.log" 2>&1 &
            echo $! > "$DPID_PID"
            log "hnc_dpid started (PID: $(cat $DPID_PID))"
        fi
    fi
fi

# ─── rc30.12.16: 进程哨兵循环 (移到末尾, 在 DPID_LAUNCHER / LAUNCHER_CHOICE 已确定后) ──
# 改自 rc30.11 sentinel. 关键修复 (rc30.12.16 P0-2):
# 之前 sentinel 在脚本前面就启动, 后台 subshell 复制了当时还空的 $DPID_LAUNCHER 变量,
# 导致死掉重启时 `[ -x "$DPID_LAUNCHER" ]` 永远为 false. 现在移到这里,
# DPID_LAUNCHER 已确定, subshell 拿到的是真实值.
#
# rc30.12.29 (P1.7): 收窄 sentinel 职责. GPT 报告指出 sentinel ↔ watchdog ↔ launcher
# 三层重叠 — watchdog 已经管 hotspotd / httpd, launcher 已经管 dpid. sentinel 不应
# 再重复管这些, 否则两个 supervisor 同时重启 → 双进程风险.
#
# 收窄后 sentinel 的职责:
#   1. dpid launcher + LAUNCHER_BROKEN 救命 (保留, 这是 rc30.12.28 真机救命路径,
#      因为 watchdog 跟 launcher 串在一起, 同样会卡 TLS abort 循环, 需要 sentinel
#      在更外层兜底跳过 launcher 直拉 dpid)
#   2. hnc_watchdog 健康 (新核心职责 — watchdog 死了 sentinel 重启它,
#      watchdog 自己接管 hotspotd / httpd)
#
# 委托给 watchdog 不再 sentinel 检查的:
#   - hnc_httpd  (watchdog.sh ensure_httpd_running)
#   - hotspotd   (watchdog.sh check_services)
(
    sleep 15
    log "sentinel: starting (launcher_choice=$LAUNCHER_CHOICE, dpid_launcher=$DPID_LAUNCHER, scope=dpid+watchdog)"

    while true; do
        # 1. dpid launcher 检查 (HANDOFF 红线 — rc30.12.28 真机救命路径, 不动)
        # rc30.12.28: 区分 direct vs launcher 模式. 之前只检查 launcher 进程,
        # 如果没有 launcher (DPID_LAUNCHER=DPID_BIN), sentinel 会一直试图启动
        # DPID_BIN 但又把它认作 launcher, 状态机错乱.
        if [ "$DPID_LAUNCHER" != "$DPID_BIN" ]; then
            # 1a. launcher 模式 - 检查 launcher 进程 (C / shell guard / Go supervisor 任一)
            LAUNCHER_ALIVE=$(ps -ef 2>/dev/null | grep -v grep \
                | grep -cE '/data/local/hnc/bin/(hnc_launcher|hnc_dpid_supervisor)|hnc_dpid_guard\.sh')
            if [ "$LAUNCHER_ALIVE" = "0" ]; then
                # rc30.12.28: 检测 launcher 反复启动失败 (TLS abort 等). 如果 dpid_guard.log
                # 最近 60 秒出现 "TLS segment is underaligned" 或类似 abort, 不要再拉 launcher,
                # 直接 fallback 到 direct mode 启动 hnc_dpid.
                LAUNCHER_BROKEN=0
                if [ -f "$HNC_DIR/logs/dpid_guard.log" ]; then
                    if tail -50 "$HNC_DIR/logs/dpid_guard.log" 2>/dev/null \
                       | grep -qE 'TLS segment is underaligned|Aborted|cannot execute|error:.*executable'; then
                        LAUNCHER_BROKEN=1
                    fi
                fi
                if [ "$LAUNCHER_BROKEN" = "1" ]; then
                    # launcher 坏了, 直接拉 dpid (绕过 launcher)
                    DPID_ALIVE=$(ps -ef 2>/dev/null | grep -v grep \
                        | grep -cE '/data/local/hnc/bin/hnc_dpid( |$)')
                    if [ "$DPID_ALIVE" = "0" ]; then
                        log "sentinel: launcher broken (abort detected), fallback to direct dpid"
                        nohup "$DPID_BIN" -config "$DPID_CONFIG" >> "$HNC_DIR/logs/dpid.log" 2>&1 &
                        echo $! > "$DPID_PID" 2>/dev/null || true
                        sleep 2
                    fi
                elif [ -x "$DPID_LAUNCHER" ]; then
                    log "sentinel: no dpid launcher running, restarting via $DPID_LAUNCHER"
                    nohup "$DPID_LAUNCHER" >> "$HNC_DIR/logs/dpid_guard.log" 2>&1 &
                    echo $! > "$DPID_GUARD_PID" 2>/dev/null || true
                    sleep 2
                else
                    log "sentinel: WARN DPID_LAUNCHER unset or not executable ($DPID_LAUNCHER), skip"
                fi
            fi
        else
            # 1b. direct 模式 - 检查 dpid 进程
            DPID_ALIVE=$(ps -ef 2>/dev/null | grep -v grep \
                | grep -cE '/data/local/hnc/bin/hnc_dpid( |$)')
            if [ "$DPID_ALIVE" = "0" ]; then
                log "sentinel: hnc_dpid not running (direct mode), relaunching"
                nohup "$DPID_BIN" -config "$DPID_CONFIG" >> "$HNC_DIR/logs/dpid.log" 2>&1 &
                echo $! > "$DPID_PID" 2>/dev/null || true
                sleep 2
            fi
        fi

        # 2. hnc_watchdog 检查 (新核心职责 — watchdog 死了 sentinel 重启它)
        # rc30.12.29 (P1.7): watchdog 是 hotspotd / httpd / dpid (常规路径) 的 supervisor,
        # 它死了 sentinel 必须兜底重启. 重启后 watchdog 自己会拉起 hotspotd / httpd,
        # sentinel 不再直接管这两个 (之前的重复检查已删, 避免双 supervisor 并发拉起).
        if ! ps -ef 2>/dev/null | grep -E '/data/local/hnc/bin/hnc_watchdog' \
             | grep -v grep > /dev/null; then
            log "sentinel: hnc_watchdog not running, relaunching"
            nohup "$HNC_DIR/bin/hnc_watchdog" \
                >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid" 2>/dev/null || true
            sleep 2
        fi

        # rc30.12.29 (P1.7): hnc_httpd / hotspotd 的检查已移除 — 委托给 watchdog.
        # 之前的 sentinel 在这里直接 launch_httpd_safe / nohup hotspotd, 跟 watchdog
        # ensure_httpd_running / check_services 并发, 触发过双进程事故.

        sleep 30
    done
) >> "$HNC_DIR/logs/sentinel.log" 2>&1 &
log "sentinel started (PID=$!, dpid_launcher=$DPID_LAUNCHER, scope=dpid+watchdog)"
