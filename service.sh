#!/system/bin/sh
# service.sh — Magisk late_start service
# 在系统完全启动后执行,可访问所有系统服务

# v3.5.0 alpha-0:PATH 健壮性
# 强制使用系统 PATH,排除 user app(MT 管理器/termux 等)对 awk/sed/grep/tc 的劫持
# 之前的隐患:如果 user 在 root shell 中调用 service.sh,继承的 PATH 可能含 user app 路径,
# 导致 HNC 用错版本的命令(行为可能跟系统 toybox 不一致)
# v5.20: 末尾追加 /data/local/hnc/bin —— /system/bin 运行期被卸时, 本进程及其全部
# 子进程(offload_guard / hotspotd 拉起的脚本等)的裸 applet 能落到 /data 副本上
# (见下方 provision_fallback_tools)。放在最后, 平时仍优先用系统命令。
[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin

# v5.9.3 BUG-009:service.sh 也会被 magiskd 直接拉起(umask=0),而且 WebUI 的
# "重启后端"是直接 fork service.sh、根本不经过 post-fs-data.sh,所以这里必须
# 有一份同款的 umask + chmod,不能只在 post-fs-data.sh 收。
# 取 022 而非 077 的理由见 post-fs-data.sh 同段注释(bin/hnc_runtime_sync.sh
# 的 `cp -rf` 同样不带 -p,077 会把脚本/二进制压到不可执行)。
umask 022

MODDIR=${0%/*}
HNC_DIR=/data/local/hnc
LOG=$HNC_DIR/logs/service.log
RUN=$HNC_DIR/run
RUN_DIR=$RUN
DATA_DIR=$HNC_DIR/data

# v5.28 A3: 哨兵的进程判活改读 /proc/<pid>/cmdline(不再依赖 ps 的输出格式,
# ColorOS 的 ps 只显示短名字曾造成进程风暴)。pid_matches / pidfile_pid_matches
# 定义在 bin/hnc_proc.sh; 优先用模块目录的副本, 运行目录副本兜底。
_HNC_PROC="$MODDIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] || _HNC_PROC="$HNC_DIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] && . "$_HNC_PROC"

mkdir -p "$HNC_DIR/logs" "$RUN"
# v6.0.0 Vector: 将 /data/local/hnc/run 挂载为 32M 内存 tmpfs (mode=0700),
# 令 shm_vector.bin 双槽 seqlock 共享内存与高频运行态快照 100% 驻留 RAM, 实现手机 UFS 闪存零擦写寿命损耗。
if [ -z "$HNC_TEST_MODE" ] && [ "$RUN" = "/data/local/hnc/run" ]; then
    if ! grep -q " $RUN tmpfs " /proc/mounts 2>/dev/null; then
        _live_daemon=0
        if [ -f "$RUN/httpd.pid" ] && command -v pidfile_pid_matches >/dev/null 2>&1; then
            pidfile_pid_matches "$RUN/httpd.pid" hnc_httpd && _live_daemon=1
        fi
        if [ "$_live_daemon" -eq 0 ]; then
            mount -t tmpfs -o size=32M,mode=0700,nosuid,nodev tmpfs "$RUN" 2>/dev/null || true
        fi
    fi
fi
# v5.9.3 BUG-009:run/ 下有 local_admin.secret(middleware 认它就给 root 级
# 写 API)。secret 文件本身早已是 0600,但目录 0777 且无 sticky 位时,别人
# 可以直接 unlink 掉它再写一个自己的 —— 收目录才是真正的修法。
chmod 700 "$HNC_DIR" "$HNC_DIR/logs" "$RUN" 2>/dev/null
[ -d "$HNC_DIR/data" ] && chmod 700 "$HNC_DIR/data" 2>/dev/null
# hotfix16.4 + v6.0 重启即焚: 清理陈旧的上行降级标记及运行态敏感瞬态文件(leakguard_events.json / shm_vector.bin)
rm -f "$RUN/uplink_unsupported" "$RUN/uplink_fail_count" "$RUN/uplink_unsupported_logged" \
      "$RUN_DIR/leakguard_events.json" "$RUN_DIR/shm_vector.bin" 2>/dev/null || true

# rc13: /system/bin resilience. SukiSU/ColorOS 在运行期会间歇性把 /system/bin 从
# 模块脚本的挂载命名空间里卸掉 → 裸命令 sleep/head/sh 等 ENOENT,watchdog/
# iptables_manager 等常驻 shell 逻辑随时崩(日志: full_init rc=-1、iptables sleep
# ENOENT)。对策: 在 /data/local/hnc/bin(在 /data,永不被卸)放一组指向已复制
# multicall 二进制的 applet 符号链接;脚本 PATH 含 /data/local/hnc/bin,/system/bin
# 一旦消失,裸命令会自动 fallthrough 到这些 /data 副本。启动时 /system 仍正常,
# 趁机复制。全程 best-effort,绝不让 service 失败。
provision_fallback_tools() {
    bbdir="$HNC_DIR/bin"
    mc=""
    _bbl="/data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox /system/xbin/busybox /system/bin/busybox"
    for _cl in "$MODDIR/bin/hnc_compat.sh" "$HNC_DIR/bin/hnc_compat.sh"; do
        [ -f "$_cl" ] || continue
        _bbx=$(HNC_COMPAT_LIB=1 . "$_cl" && hnc_busybox_candidates | tr '\n' ' ')
        [ -n "$_bbx" ] && _bbl="$_bbx"
        break
    done
    for c in $_bbl /system/bin/toybox; do
        [ -x "$c" ] && { mc="$c"; break; }
    done
    if [ -n "$mc" ] && cp -f "$mc" "$bbdir/.hnc_mc" 2>/dev/null; then
        chmod 755 "$bbdir/.hnc_mc" 2>/dev/null
        _al=" $("$bbdir/.hnc_mc" --list 2>/dev/null | tr '\n' ' ') "
        [ "$_al" = "  " ] && _al=" $("$bbdir/.hnc_mc" 2>/dev/null | tr '\n' ' ') "
        _core="sleep head tail cat printf date grep sed cut tr wc"
        _extra="awk rm mkdir mv touch dirname basename stat readlink sort uniq find ln chmod chown id seq pidof ps xargs"
        for ap in $_core $_extra; do
            if [ "$_al" != "  " ]; then
                case "$_al" in *" $ap "*) ln -sf .hnc_mc "$bbdir/$ap" 2>/dev/null ;; esac
            else
                case " $_core " in *" $ap "*) ln -sf .hnc_mc "$bbdir/$ap" 2>/dev/null ;; esac
            fi
        done
        command -v log >/dev/null 2>&1 && log "rc15: provisioned fallback applets from $mc -> $bbdir"
    fi
    if [ -x "$bbdir/.hnc_mc" ] && "$bbdir/.hnc_mc" ash -c 'exit 0' 2>/dev/null; then
        ln -sf .hnc_mc "$bbdir/sh" 2>/dev/null
    elif [ -e /system/bin/mksh ] && cp -fL /system/bin/mksh "$bbdir/sh" 2>/dev/null; then
        chmod 755 "$bbdir/sh" 2>/dev/null
    elif [ -e /system/bin/sh ] && cp -fL /system/bin/sh "$bbdir/sh" 2>/dev/null; then
        chmod 755 "$bbdir/sh" 2>/dev/null
    fi
}
provision_fallback_tools 2>/dev/null || true

# rc3.1 修 N-15R: 记下自己路径让 cleanup.sh restart 时能找到我们
echo "$MODDIR" > "$RUN/service.path" 2>/dev/null

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HNC] $1" >> "$LOG"
}

# v5.20: 兼容性环境快照
_HNC_COMPAT="$MODDIR/bin/hnc_compat.sh"
[ -f "$_HNC_COMPAT" ] || _HNC_COMPAT="$HNC_DIR/bin/hnc_compat.sh"
if [ -f "$_HNC_COMPAT" ]; then
    HNC_DIR="$HNC_DIR" sh "$_HNC_COMPAT" root >/dev/null 2>&1 || true
    log "v5.20 compat: $(tr -d '\n' < "$RUN/root_env.json" 2>/dev/null | cut -c1-400)"
    case "$(cat "$RUN/root_env.json" 2>/dev/null)" in
        *'"module_webui":false'*) log "v5.20 compat: 当前 root 方案无模块 WebUI, 请用浏览器打开 $(cat "$RUN/webui_url" 2>/dev/null)" ;;
    esac
fi
rm -f "$RUN/iface_detect.json" 2>/dev/null

is_pid_alive() {
    [ -n "$1" ] && kill -0 "$1" 2>/dev/null
}

process_by_name_alive() {
    local n
    n="$1"
    [ -z "$n" ] && return 1
    pidof "$n" >/dev/null 2>&1 && return 0
    ps -ef 2>/dev/null | awk -v n="$n" '
        $0 !~ /awk/ && $0 !~ /grep/ {
            if ($0 ~ ("(^|[ /])" n "([[:space:]]|$)")) found=1
        }
        END { exit found ? 0 : 1 }
    '
}

list_watchdog_pids() {
    (
        pidof hnc_watchdog 2>/dev/null | tr ' ' '\n'
        ps -ef 2>/dev/null | awk '
            $0 !~ /awk/ && $0 !~ /grep/ && $0 ~ /(^|[ /])(hnc_watchdog|watchdog\.sh)([[:space:]]|$)/ { print $2 }
        '
    ) | awk 'NF && !seen[$1]++ { print $1 }'
}

find_live_watchdog_pid() {
    local p _wp
    if pidfile_pid_matches "$RUN/watchdog.pid" hnc_watchdog; then
        _wp="$(cat "$RUN/watchdog.pid" 2>/dev/null | tr -d ' \r\n')"
        echo "$_wp"
        return 0
    fi
    for p in $(list_watchdog_pids); do
        if is_pid_alive "$p"; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

prune_duplicate_watchdogs() {
    local reason pids count keep p
    reason="$1"
    pids="$(list_watchdog_pids | tr '\n' ' ')"
    count=$(echo "$pids" | wc -w | tr -d ' ')
    [ -z "$count" ] && count=0
    [ "$count" -le 1 ] && return 0

    keep=$(cat "$RUN/watchdog.pid" 2>/dev/null)
    case " $pids " in
        *" $keep "*) ;;
        *) keep="" ;;
    esac
    if [ -z "$keep" ]; then
        keep=$(echo "$pids" | tr ' ' '\n' | awk 'NF' | sort -n | head -n 1)
    fi
    [ -n "$keep" ] && echo "$keep" > "$RUN/watchdog.pid" 2>/dev/null || true
    log "watchdogfix-v6.1: duplicate watchdogs detected count=$count keep=$keep reason=$reason"

    for p in $pids; do
        [ -z "$p" ] && continue
        [ "$p" = "$keep" ] && continue
        kill "$p" 2>/dev/null || true
    done
    sleep 0.3 2>/dev/null || sleep 1
    for p in $pids; do
        [ -z "$p" ] && continue
        [ "$p" = "$keep" ] && continue
        if is_pid_alive "$p"; then
            kill -9 "$p" 2>/dev/null || true
            log "watchdogfix-v6.1: KILL duplicate hnc_watchdog pid=$p keep=$keep"
        fi
    done
}

prune_stale_service_sentinels() {
    local self proot old_spid sp_cmd pids d p cl
    self=$$
    proot="${HNC_PROC_ROOT:-/proc}"
    if [ "$MODDIR" != "/data/adb/modules/hotspot_network_control" ] && [ -d "/data/adb/modules/hotspot_network_control" ]; then
        : > "/data/adb/modules/hotspot_network_control/disable" 2>/dev/null || true
        : > "/data/adb/modules/hotspot_network_control/remove" 2>/dev/null || true
    fi
    pids=""
    # v6.0: 删除 sentinel.pid 前必须先读出旧哨兵 PID 并校验 /proc/<pid>/cmdline 含 service.sh,
    # 优雅终止后再删 pidfile, 根治重启后端时旧后台哨兵 subshell 残留堆积!
    if [ -f "$RUN/sentinel.pid" ]; then
        old_spid=$(cat "$RUN/sentinel.pid" 2>/dev/null | tr -dc '0-9')
        if [ -n "$old_spid" ] && [ "$old_spid" != "$self" ] && [ -r "$proot/$old_spid/cmdline" ]; then
            sp_cmd=$(tr '\000' ' ' < "$proot/$old_spid/cmdline" 2>/dev/null)
            case "$sp_cmd" in
                *service.sh*) pids="$old_spid" ;;
            esac
        fi
    fi
    # 扫描 /proc/<pid>/cmdline 兜底捕获未登记在 sentinel.pid 的旧 service.sh 实例(不依赖截断的 ps)
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        [ "$p" = "$self" ] && continue
        cl=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
        case "$cl" in
            *hotspot_net_ctl/service.sh*|*hotspot_network_control/service.sh*|*/data/adb/hnc/service.sh*|*"$MODDIR/service.sh"*)
                pids="$pids $p"
                ;;
        esac
    done
    pids=$(printf '%s\n' $pids | awk 'NF && !seen[$1]++ { print $1 }' | tr '\n' ' ')
    if [ -n "$pids" ]; then
        log "v6.0: stopping stale service/sentinel pids: $pids"
        for p in $pids; do
            [ -n "$p" ] && kill "$p" 2>/dev/null || true
        done
        sleep 0.3 2>/dev/null || sleep 1
        for p in $pids; do
            [ -z "$p" ] && continue
            if is_pid_alive "$p"; then
                kill -9 "$p" 2>/dev/null || true
                log "v6.0: KILL stale service/sentinel pid=$p"
            fi
        done
    fi
    rm -f "$RUN/sentinel.pid" 2>/dev/null || true
}

# Kill old buggy sentinel/service shells before this fixed service starts supervisors.
prune_stale_service_sentinels

log "=== HNC Service Starting ==="
log "Android $(getprop ro.build.version.release) / $(getprop ro.product.brand) $(getprop ro.product.model)"

# v5.29 T3: 升级快照 + 钉住检查
_RB=0
if [ -f "$MODDIR/bin/hnc_rollback.sh" ]; then
    HNC_RB_LOG="$HNC_DIR/logs/rollback.log" sh "$MODDIR/bin/hnc_rollback.sh" snapshot "$MODDIR" "$HNC_DIR"
    _RB=$?
fi
if [ "$_RB" = 3 ]; then
    log "rollback: version pinned, skip runtime sync (staying on .prev)"
    sh "$MODDIR/bin/hnc_runtime_sync.sh" perms "$MODDIR" "$HNC_DIR" >> "$LOG" 2>&1
else
    sh "$MODDIR/bin/hnc_runtime_sync.sh" sync "$MODDIR" "$HNC_DIR" >> "$LOG" 2>&1
fi

# v5.22 (armeabi-v7a): ABI 兜底。正常安装由 customize.sh 选好二进制并删掉
# bin/<abi>/ 覆盖层; 若安装器没跑 customize.sh(覆盖层随 cp -rf 进了运行目录),
# 这里按设备 ABI 在 $HNC_DIR 上就地补做一次, 并对包/设备 ABI 不符打日志。
if [ -f "$HNC_DIR/bin/hnc_arch.sh" ]; then
    . "$HNC_DIR/bin/hnc_arch.sh"
    _hnc_dev_abi=$(hnc_arch_device_abi)
    if [ -d "$HNC_DIR/bin/$_hnc_dev_abi" ]; then
        if hnc_arch_apply_overlay "$HNC_DIR" "$_hnc_dev_abi" >/dev/null 2>&1; then
            for _b in "$HNC_DIR/bin/$_hnc_dev_abi"/*; do
                [ -f "$_b" ] || continue
                _b=${_b##*/}
                [ "$_b" = hnc_httpd ] && _b="../daemon/hnc_httpd/hnc_httpd"
                chcon u:object_r:system_file:s0 "$HNC_DIR/bin/$_b" 2>/dev/null || true
            done
            log "v5.22 ABI: applied runtime overlay bin/$_hnc_dev_abi (customize.sh did not run?)"
        else
            log "v5.22 ABI WARN: failed to apply runtime overlay bin/$_hnc_dev_abi"
        fi
    fi
    hnc_arch_remove_overlays "$HNC_DIR"
    _hnc_pkg_abi=$(hnc_arch_pkg_abi "$HNC_DIR")
    if [ "$_hnc_pkg_abi" = "$_hnc_dev_abi" ]; then
        log "v5.22 ABI: device=$_hnc_dev_abi binaries=$_hnc_pkg_abi"
    else
        log "v5.22 ABI ERROR: device=$_hnc_dev_abi but binaries=$_hnc_pkg_abi — 刷错了安装包? 原生二进制将无法执行"
    fi
    unset _hnc_dev_abi _hnc_pkg_abi _b
fi

# v6.x 升级迁移: nDPI 实验已整体移除
migrate_remove_ndpi() {
    _np=$(cat "$RUN/ndpi_continuous.pid" 2>/dev/null)
    case "$_np" in
        ''|*[!0-9]*) _np="" ;;
    esac
    if [ -n "$_np" ] && kill -0 "$_np" 2>/dev/null \
       && grep -q "ndpi_continuous" "/proc/$_np/cmdline" 2>/dev/null; then
        kill "$_np" 2>/dev/null
        sleep 1
        kill -9 "$_np" 2>/dev/null
        log "migrate: stopped legacy ndpi_continuous.sh pid=$_np"
    fi
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "$HNC_DIR/bin/hnc_ndpi_probe" 2>/dev/null || true
    fi
    _nd_removed=0
    for _f in "$RUN/ndpi_continuous.pid" "$RUN/ndpi_continuous_current.csv" \
              "$RUN/ndpi_continuous_pending.csv" "$RUN/quic_dns_observations.json" \
              "$RUN/ip_to_host.json" "$RUN/ndpi_lab_state.json" \
              "$RUN/ndpi_lab_sample.txt" "$RUN/ndpi_lab_sample.json" \
              "$RUN/ndpi_lab_sample_state.json" "$RUN/ndpi_lab_sample_structured.json" \
              "$HNC_DIR/logs/ndpi_continuous.log" "$HNC_DIR/logs/ndpi_lab.log" \
              "$HNC_DIR/etc/dpi_ndpi_config.json" "$HNC_DIR/data/dpi_ndpi_config.json" \
              "$HNC_DIR/bin/hnc_ndpi_probe" "$HNC_DIR/bin/ndpiReader" "$HNC_DIR/bin/hnc_dpid_ndpi" \
              "$HNC_DIR/bin/ndpi_continuous.sh" "$HNC_DIR/bin/ndpi_lab_probe.sh" \
              "$HNC_DIR/bin/ndpi_lab_sample.sh" "$HNC_DIR/bin/ndpi_lab_status.sh" \
              "$HNC_DIR/bin/ndpi_parse_observations.sh" \
              "$HNC_DIR/webroot/ndpi-lab.html" "$HNC_DIR/webroot/classic.html"; do
        if [ -e "$_f" ]; then
            rm -f "$_f" 2>/dev/null && _nd_removed=$((_nd_removed + 1))
        fi
    done
    for _f in "$HNC_DIR"/bin/stats_shadow_*.sh "$HNC_DIR"/bin/stats_v52_*.sh "$HNC_DIR"/bin/stats_v52_README.md \
              "$HNC_DIR/bin/stats_compare.sh" "$HNC_DIR/bin/stats_migration_readiness.sh" \
              "$HNC_DIR/bin/stats_source_diag.sh" "$RUN/stats_shadow.enabled" \
              "$RUN/stats_v52_rc.enabled" "$RUN/stats_v52_rc1.enabled"; do
        if [ -e "$_f" ]; then
            rm -f "$_f" 2>/dev/null && _nd_removed=$((_nd_removed + 1))
        fi
    done
    [ "$_nd_removed" -gt 0 ] && log "migrate: removed $_nd_removed legacy nDPI/shadow-stats file(s)"
    return 0
}
migrate_remove_ndpi

if [ -f "$HNC_DIR/bin/capability_probe.sh" ]; then
    ( HNC="$HNC_DIR" sh "$HNC_DIR/bin/capability_probe.sh" >> "$HNC_DIR/logs/capabilities.log" 2>&1 ) &
fi

if [ -x "$HNC_DIR/bin/ahnc_migration.sh" ]; then
    ( sh "$HNC_DIR/bin/ahnc_migration.sh" >> "$HNC_DIR/logs/migration.log" 2>&1 ) &
fi

wait_for_network() {
    local max=60
    local cnt=0
    while [ $cnt -lt $max ]; do
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

log "v4.0.0-patch1.5 Defer Init: iface detection + tc/iptables init delegated to watchdog"

# ─── rc30.12.18: auth_required 自动迁移到默认拒绝 ────────────────
RULES_JSON="$HNC_DIR/data/rules.json"
if [ -f "$RULES_JSON" ]; then
    CUR_AUTH=$(grep -o '"auth_required"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$RULES_JSON" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')
    if [ "$CUR_AUTH" = "false" ]; then
        log "rc30.12.18 migration: auth_required=false in rules.json detected, auto-upgrading to true"
        log "  (rc30.12.18 enforces default-deny regardless; this just keeps WebUI toggle consistent)"
        JSON_SET="$MODDIR/bin/json_set.sh"
        [ -f "$JSON_SET" ] || JSON_SET="$HNC_DIR/bin/json_set.sh"
        if HNC=$HNC_DIR sh "$JSON_SET" top auth_required true >/dev/null 2>&1; then
            log "auth_required migrated to true via json_set.sh (locked writer)"
        else
            log "WARN: auth_required migration via json_set.sh failed rc=$? (cosmetic only)"
        fi
    fi
fi

# 验证 hnc_httpd binary 存在且可执行
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
LOCAL_ADMIN_SECRET="$RUN/local_admin.secret"
if [ ! -s "$LOCAL_ADMIN_SECRET" ]; then
    if [ -r /dev/urandom ]; then
        SECRET_VAL=$(head -c 32 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' 2>/dev/null)
    fi
    if [ -z "$SECRET_VAL" ] && [ -r /proc/sys/kernel/random/uuid ]; then
        SECRET_VAL=$( { cat /proc/sys/kernel/random/uuid /proc/sys/kernel/random/uuid \
                            /proc/sys/kernel/random/uuid 2>/dev/null; } | tr -dc '0-9a-f' | cut -c1-64 )
        [ "${#SECRET_VAL}" -eq 64 ] || SECRET_VAL=""
    fi
    if [ -n "$SECRET_VAL" ]; then
        ( umask 077; printf "%s" "$SECRET_VAL" > "$LOCAL_ADMIN_SECRET" )
        chmod 600 "$LOCAL_ADMIN_SECRET" 2>/dev/null
        chown root:root "$LOCAL_ADMIN_SECRET" 2>/dev/null
        log "rc30.12.14: generated local admin secret ($LOCAL_ADMIN_SECRET, mode 0600)"
    else
        log "v5.8.8: WARN no CSPRNG available, NOT generating local_admin.secret — loopback write/sensitive paths stay fail-closed (cookie required), no weak-entropy fallback"
    fi
fi

# ─── 拉起 hotspotd(硬件加速兜底 + 控制接口)───────────────────
log "Starting hotspotd (offload + control socket; device discovery is the Go watchdog's)..."
rm -f "$RUN/detect.pid" 2>/dev/null
sh "$HNC_DIR/bin/device_detect.sh" daemon >> "$HNC_DIR/logs/detect.log" 2>&1 &
HPID=""
i=0
while [ $i -lt 50 ]; do
    HPID=$(pidfile_live_pid "$RUN/hotspotd.pid" hotspotd)
    [ -n "$HPID" ] && kill -0 "$HPID" 2>/dev/null && break
    if usleep 100000 2>/dev/null; then
        i=$((i + 1))
    else
        sleep 1
        i=$((i + 10))
    fi
done
if [ -n "$HPID" ] && kill -0 "$HPID" 2>/dev/null; then
    log "hotspotd running (PID=$HPID)"
else
    log "WARN: hotspotd not up after 5s (watchdog will retry; device list unaffected)"
fi
prune_duplicate_hotspotd

# ─── v5.22: WebUI 访问白名单落防火墙(必须在 httpd 开监听之前) ────────
if [ -f "$HNC_DIR/bin/webui_guard.sh" ]; then
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$HNC_DIR/logs/service.log" 2>&1 \
        || log "v5.22: WARN webui_guard apply failed (HTTP-level guard in hnc_httpd still active)"
fi

# ─── rc30.12: shell pre-launch hnc_httpd ─────────────────────
launch_httpd_safe() {
    nohup "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" -hnc-dir "$HNC_DIR" \
        >> "$HNC_DIR/logs/httpd.log" 2>&1 &
    echo $! > "$RUN/httpd.pid" 2>/dev/null || true
    log "launch_httpd_safe: hnc_httpd started (PID=$!; remote port follows remote_enabled)"
}

# v5.40.1: 基于 /proc/<pid>/cmdline 清理旧模块残留的重复 hnc_httpd 实例
prune_duplicate_httpds() {
    local proot="${HNC_PROC_ROOT:-/proc}"
    local keep="" d p cmd count=0 all_pids=""
    keep=$(cat "$RUN/httpd.pid" 2>/dev/null | tr -dc '0-9')
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        cmd=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
        case "$cmd" in
            *hnc_httpd*)
                case "$cmd" in
                    *" -port "*|*" -loopback-port "*|*hotspot_network_control*)
                        kill "$p" 2>/dev/null || true
                        usleep 100000 2>/dev/null || sleep 1
                        kill -9 "$p" 2>/dev/null || true
                        log "v5.40.1: terminated legacy hnc_httpd instance pid=$p"
                        continue
                        ;;
                esac
                all_pids="$all_pids $p"
                count=$((count + 1))
                ;;
        esac
    done
    if [ "$count" -gt 1 ]; then
        case " $all_pids " in
            *" $keep "*) ;;
            *) keep=$(printf '%s\n' $all_pids | sort -n | head -n 1) ;;
        esac
        [ -n "$keep" ] && echo "$keep" > "$RUN/httpd.pid" 2>/dev/null || true
        for p in $all_pids; do
            [ "$p" = "$keep" ] && continue
            kill "$p" 2>/dev/null || true
            usleep 100000 2>/dev/null || sleep 1
            kill -9 "$p" 2>/dev/null || true
            log "v5.40.1: terminated duplicate hnc_httpd pid=$p (kept=$keep)"
        done
    fi
}

find_live_httpd_by_proc() {
    local proot="${HNC_PROC_ROOT:-/proc}"
    local d p
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        if pid_matches "$p" hnc_httpd; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

if [ -x "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" ]; then
    prune_duplicate_httpds
    HP=$(pidfile_live_pid "$RUN/httpd.pid" hnc_httpd 2>/dev/null)
    if [ -z "$HP" ]; then
        HP=$(find_live_httpd_by_proc)
    fi
    if [ -n "$HP" ] && kill -0 "$HP" 2>/dev/null; then
        echo "$HP" > "$RUN/httpd.pid" 2>/dev/null || true
        log "rc30.12 pre-launch: hnc_httpd already running (PID=$HP)"
    else
        launch_httpd_safe
        sleep 1
        prune_duplicate_httpds
    fi
fi

# ─── 启动 Watchdog ──────────────────────────────────────────
log "Starting watchdog..."
prune_duplicate_watchdogs "service-prestart"
WPID=$(pidfile_live_pid "$RUN/watchdog.pid" hnc_watchdog)
if [ -n "$WPID" ] && kill -0 "$WPID" 2>/dev/null; then
    log "watchdog already running (PID=$WPID), skip duplicate launch"
else
    LIVE_WD=$(find_live_watchdog_pid)
    if [ -n "$LIVE_WD" ] && kill -0 "$LIVE_WD" 2>/dev/null; then
        echo "$LIVE_WD" > "$RUN/watchdog.pid" 2>/dev/null || true
        log "watchdog live without pidfile (PID=$LIVE_WD), repaired pidfile"
    else
        rm -f "$RUN/watchdog.pid" 2>/dev/null || true
        if [ -x "$HNC_DIR/bin/hnc_watchdog" ]; then
            nohup "$HNC_DIR/bin/hnc_watchdog" >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid"
            log "watchdog (Go, rc30.1+) started (PID=$(cat "$RUN/watchdog.pid" 2>/dev/null))"
        else
            log "FATAL: bin/hnc_watchdog missing, watchdog not started"
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
(
    sleep 3
    RULES="$HNC_DIR/data/rules.json"
    HNC_IPC="$HNC_DIR/bin/hnc_ipc"
    [ -f "$RULES" ] && [ -x "$HNC_IPC" ] || exit 0

    RECOVERED=0
    for MAC in $(grep -oE '"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"[^}]*"limit_enabled"[[:space:]]*:[[:space:]]*true' "$RULES" \
                 | grep -oE '^"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"' \
                 | tr -d '"'); do
        "$HNC_IPC" OFFLOAD_NOTIFY_LIMIT "$MAC" 1 >/dev/null 2>&1 && RECOVERED=$((RECOVERED+1))
    done
    if [ "$RECOVERED" -gt 0 ]; then
        log "offload recovery: notified $RECOVERED limited device(s) to scheduler"
    fi
) &

# ─── 热点自动启动 ────────────────────────────────────────────
HOTSPOT_AUTO=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_auto 2>/dev/null \
    || grep -o '"hotspot_auto"[[:space:]]*:[[:space:]]*[a-z]*' "$HNC_DIR/data/rules.json" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')

if [ "$HOTSPOT_AUTO" = "true" ]; then
    log "hotspot_auto=true, launching hotspot_autostart.sh in background..."
    (sleep 5 && sh "$HNC_DIR/bin/hotspot_autostart.sh" start) \
        >> "$HNC_DIR/logs/hotspot.log" 2>&1 &
    echo $! > "$RUN/hotspot.pid"
    log "Hotspot autostart scheduled (PID: $(cat "$RUN/hotspot.pid" 2>/dev/null))"
else
    log "hotspot_auto=false, skipping autostart"
fi

# ─── hnc_dpid (DPI 被动观察 daemon, v5.3.0-rc12 新增) ────────────
DPID_BIN="$HNC_DIR/bin/hnc_dpid"
DPID_LAUNCHER_C="$HNC_DIR/bin/hnc_launcher"
FORK_PROBE="$HNC_DIR/bin/fork_probe"
DPID_LAUNCHER="$DPID_BIN"
DPID_CONFIG="$HNC_DIR/etc/dpi_config.json"
DPID_PID="$RUN/dpid.pid"
DPID_GUARD_PID="$RUN/dpid_guard.pid"

find_live_dpid_guard_pid() {
    local proot="${HNC_PROC_ROOT:-/proc}"
    local d p
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        if pid_matches "$p" hnc_launcher; then
            echo "$p"
            return 0
        fi
    done
    ps -ef 2>/dev/null | awk '$0 !~ /awk/ && $0 ~ /(^|[ \/])hnc_launcher([ \t]|$)/ { print $2; exit }'
}

# rc30.12 launcher 探测
LAUNCHER_CHOICE=""
if [ -x "$DPID_LAUNCHER_C" ] && [ -x "$FORK_PROBE" ]; then
    if "$FORK_PROBE" /system/bin/true >/dev/null 2>&1; then
        _launcher_test=$("$DPID_LAUNCHER_C" --version 2>&1)
        _launcher_test_rc=$?
        if echo "$_launcher_test" | grep -qE 'underaligned|Aborted|cannot execute|error:.*executable'; then
            log "dpid launcher: hnc_launcher binary broken (TLS/Bionic mismatch), skip"
            log "  diag: $(echo "$_launcher_test" | head -n 1)"
        elif [ "$_launcher_test_rc" = "134" ] || [ "$_launcher_test_rc" = "137" ]; then
            log "dpid launcher: hnc_launcher aborted (rc=$_launcher_test_rc), skip"
        else
            DPID_LAUNCHER="$DPID_LAUNCHER_C"
            LAUNCHER_CHOICE="c_launcher"
            log "dpid launcher: hnc_launcher (C, rc30.12+) — fork_probe PASS + exec PASS"
        fi
        unset _launcher_test _launcher_test_rc
    else
        log "dpid launcher: fork_probe FAIL on this device"
    fi
fi

if [ -z "$LAUNCHER_CHOICE" ]; then
    log "dpid launcher: C launcher unavailable, direct mode (Go watchdog supervises hnc_dpid)"
fi

case "$LAUNCHER_CHOICE" in
    c_launcher)     _dpid_choice="launcher" ;;
    *)              _dpid_choice="direct" ;;
esac
printf '%s\n' "$_dpid_choice" > "$RUN/dpid_launcher.choice.tmp" 2>/dev/null \
    && mv -f "$RUN/dpid_launcher.choice.tmp" "$RUN/dpid_launcher.choice" 2>/dev/null \
    || printf '%s\n' "$_dpid_choice" > "$RUN/dpid_launcher.choice" 2>/dev/null
log "dpid launcher choice persisted: $_dpid_choice (raw=$LAUNCHER_CHOICE)"
unset _dpid_choice


if [ ! -x "$DPID_BIN" ]; then
    log "WARN: hnc_dpid binary missing at $DPID_BIN, DPI 功能不可用"
else
    mkdir -p "$HNC_DIR/etc" 2>/dev/null || true
    chmod 755 "$HNC_DIR/etc" 2>/dev/null || true

    # v6.0: 仅当用户持久显式同意文件 $DATA_DIR/self_capture.optin 存在时才在开机启用本机抓包,
    # 彻底根治默认开机无条件每 10 秒跑 dumpsys activity 唤醒 ActivityTaskManager 的耗电黑洞!
    if [ -f "$DATA_DIR/self_capture.optin" ]; then
        if [ ! -f "$RUN/self_capture.enabled" ]; then
            : > "$RUN/self_capture.enabled" 2>/dev/null && chmod 644 "$RUN/self_capture.enabled" 2>/dev/null
        fi
        log "dpid: self-capture opt-in present ($DATA_DIR/self_capture.optin) — created $RUN/self_capture.enabled"
    else
        rm -f "$RUN/self_capture.enabled" 2>/dev/null || true
        log "dpid: self-capture default-off (no $DATA_DIR/self_capture.optin)"
    fi

    if [ ! -f "$DPID_CONFIG" ] && [ -f "$MODDIR/data/dpi_config.json" ]; then
        cp -f "$MODDIR/data/dpi_config.json" "$DPID_CONFIG" 2>/dev/null
        chmod 644 "$DPID_CONFIG" 2>/dev/null
        log "dpid: installed default dpi_config.json to $DPID_CONFIG"
    fi

    MOD_RULES_D="$MODDIR/data/dpi_rules.d"
    DPID_RULES_D="$HNC_DIR/etc/dpi_rules.d"
    if [ -d "$MOD_RULES_D" ]; then
        _RSYNC="$MODDIR/bin/dpi_rules_sync.sh"
        [ -f "$_RSYNC" ] || _RSYNC="$HNC_DIR/bin/dpi_rules_sync.sh"
        if [ -f "$_RSYNC" ] && sh "$_RSYNC" "$MOD_RULES_D" "$DPID_RULES_D" "$MODDIR/module.prop" >> "$LOG" 2>&1; then
            log "dpid: synced dpi_rules.d/ ($(find "$DPID_RULES_D" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l) subset files) to $DPID_RULES_D"
        else
            log "dpid: WARN dpi_rules.d sync failed (see logs/dpi_rules_sync.log); keeping existing $DPID_RULES_D"
        fi
    fi

    DPID_BLOCKLIST="$HNC_DIR/etc/auto_expand_blocklist.json"
    if [ ! -f "$DPID_BLOCKLIST" ] && [ -f "$MODDIR/data/auto_expand_blocklist.json" ]; then
        cp -f "$MODDIR/data/auto_expand_blocklist.json" "$DPID_BLOCKLIST" 2>/dev/null
        chmod 644 "$DPID_BLOCKLIST" 2>/dev/null
        log "dpid: installed default auto_expand_blocklist.json to $DPID_BLOCKLIST"
    elif [ -f "$DPID_BLOCKLIST" ] && [ -f "$MODDIR/data/auto_expand_blocklist.json" ]; then
        _BLK_TMP="$DPID_BLOCKLIST.merge.$$"
        if awk '
            FNR == NR {
                if (match($0, /"[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"/)) {
                    d = substr($0, RSTART + 1, RLENGTH - 2)
                    if (d !~ / /) seen[tolower(d)] = 1
                }
                lines[++n] = $0
                next
            }
            {
                if (match($0, /"[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"/)) {
                    d = substr($0, RSTART + 1, RLENGTH - 2)
                    dl = tolower(d)
                    if (d !~ / / && !(dl in seen)) {
                        seen[dl] = 1
                        add[++m] = dl
                    }
                }
            }
            END {
                if (m == 0) exit 2
                ins = 0
                for (i = n; i >= 1; i--) {
                    if (lines[i] ~ /\]/) { ins = i; break }
                }
                if (ins == 0) exit 1
                prev = ins - 1
                while (prev >= 1 && lines[prev] ~ /^[[:space:]]*$/) prev--
                if (prev >= 1 && lines[prev] !~ /\[[[:space:]]*$/ && lines[prev] !~ /,[[:space:]]*$/) {
                    sub(/[[:space:]]*$/, ",", lines[prev])
                }
                for (i = 1; i <= n; i++) {
                    if (i == ins) {
                        for (j = 1; j <= m; j++) {
                            sep = (j < m) ? "," : ""
                            print "    \"" add[j] "\"" sep
                        }
                    }
                    print lines[i]
                }
            }
        ' "$DPID_BLOCKLIST" "$MODDIR/data/auto_expand_blocklist.json" > "$_BLK_TMP" 2>/dev/null && [ -s "$_BLK_TMP" ]; then
            chmod 644 "$_BLK_TMP" 2>/dev/null || true
            mv -f "$_BLK_TMP" "$DPID_BLOCKLIST" 2>/dev/null && log "dpid: merged newly shipped shared-infra apexes into $DPID_BLOCKLIST"
        else
            rm -f "$_BLK_TMP" 2>/dev/null || true
        fi
    fi

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

    DPID_JA4="$HNC_DIR/etc/dpi_ja4_fingerprints.json"
    if [ ! -f "$DPID_JA4" ] && [ -f "$MODDIR/data/dpi_ja4_fingerprints.json" ]; then
        cp -f "$MODDIR/data/dpi_ja4_fingerprints.json" "$DPID_JA4" 2>/dev/null
        chmod 644 "$DPID_JA4" 2>/dev/null
        log "dpid: installed default dpi_ja4_fingerprints.json to $DPID_JA4"
    fi

    if [ "$DPID_LAUNCHER" != "$DPID_BIN" ]; then
        gp=$(pidfile_live_pid "$DPID_GUARD_PID" hnc_launcher)
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
        dp=$(pidfile_live_pid "$DPID_PID" hnc_dpid)
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

# ─── rc30.12.16: 进程哨兵循环 ──────────────────────────────────
(
    sleep 15
    log "sentinel: starting (launcher_choice=$LAUNCHER_CHOICE, dpid_launcher=$DPID_LAUNCHER, scope=watchdog(+rollback); dpid->launcher+go-watchdog)"

    while true; do
        prune_duplicate_watchdogs "sentinel-loop"
        if ! find_live_watchdog_pid >/dev/null 2>&1; then
            log "sentinel: hnc_watchdog not running, relaunching"
            nohup "$HNC_DIR/bin/hnc_watchdog" \
                >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid" 2>/dev/null || true
            sleep 2
        fi

        if [ -f "$HNC_DIR/data/rollback.observing" ] && [ -f "$HNC_DIR/bin/hnc_rollback.sh" ]; then
            HNC_RB_LOG="$HNC_DIR/logs/rollback.log" sh "$HNC_DIR/bin/hnc_rollback.sh" observe "$HNC_DIR"
        fi

        sleep 30
    done
) >> "$HNC_DIR/logs/sentinel.log" 2>&1 &
echo $! > "$RUN/sentinel.pid" 2>/dev/null || true
log "sentinel started (PID=$(cat "$RUN/sentinel.pid" 2>/dev/null), dpid_launcher=$DPID_LAUNCHER, scope=watchdog+rollback, v6.0)"
