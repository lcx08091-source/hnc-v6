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

# v5.28 A3: 哨兵的进程判活改读 /proc/<pid>/cmdline(不再依赖 ps 的输出格式,
# ColorOS 的 ps 只显示短名字曾造成进程风暴)。pid_matches / pidfile_pid_matches
# 定义在 bin/hnc_proc.sh; 优先用模块目录的副本, 运行目录副本兜底。
_HNC_PROC="$MODDIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] || _HNC_PROC="$HNC_DIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] && . "$_HNC_PROC"

mkdir -p "$HNC_DIR/logs" "$RUN"
# v5.9.3 BUG-009:run/ 下有 local_admin.secret(middleware 认它就给 root 级
# 写 API)。secret 文件本身早已是 0600,但目录 0777 且无 sticky 位时,别人
# 可以直接 unlink 掉它再写一个自己的 —— 收目录才是真正的修法。
chmod 700 "$HNC_DIR" "$HNC_DIR/logs" "$RUN" 2>/dev/null
[ -d "$HNC_DIR/data" ] && chmod 700 "$HNC_DIR/data" 2>/dev/null
# hotfix16.4: clear stale uplink degraded marker on service start; watchdog will re-probe.
rm -f "$RUN/uplink_unsupported" "$RUN/uplink_fail_count" "$RUN/uplink_unsupported_logged" 2>/dev/null || true

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
    # rc15: 优先用常驻 /data 上、且 applet 更全(含 awk)的 busybox 作 multicall 源。
    # KSU/Magisk 的 busybox 在 /data,永不被卸且一直在;toybox 的 applet 更少、很多
    # ROM 的 toybox 还不带 awk(我们常驻循环 awk 用得很多)。system 的 busybox/toybox
    # 作兜底(启动时 /system 仍正常,拷到 /data 后即使后续 /system 被卸,副本仍在)。
    # v5.20: 按当前 root 方案排序(KernelSU/SukiSU → ksu, APatch → ap, Magisk → magisk),
    # 换过 root 方案残留的旧 busybox 排后面; 补上 APatch 的 /data/adb/ap/bin/busybox。
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
        # 只给该 multicall 二进制真正支持的 applet 建符号链接,避免建出"调用即报
        # unknown applet"的死链接。busybox 用 --list;toybox 无参时打印 applet 列表。
        _al=" $("$bbdir/.hnc_mc" --list 2>/dev/null | tr '\n' ' ') "
        [ "$_al" = "  " ] && _al=" $("$bbdir/.hnc_mc" 2>/dev/null | tr '\n' ' ') "
        _core="sleep head tail cat printf date grep sed cut tr wc"
        _extra="awk rm mkdir mv touch dirname basename stat readlink sort uniq find ln chmod chown id seq pidof ps xargs"
        for ap in $_core $_extra; do
            if [ "$_al" != "  " ]; then
                case "$_al" in *" $ap "*) ln -sf .hnc_mc "$bbdir/$ap" 2>/dev/null ;; esac
            else
                # applet 列表探测失败:只建 toybox/busybox 都必有的核心集,绝不乱建
                case " $_core " in *" $ap "*) ln -sf .hnc_mc "$bbdir/$ap" 2>/dev/null ;; esac
            fi
        done
        command -v log >/dev/null 2>&1 && log "rc15: provisioned fallback applets from $mc -> $bbdir"
    fi
    # sh: 脚本是 mksh 方言([[ ]] / (( )) / function),必须用 mksh,不能换 busybox ash
    if [ -e /system/bin/mksh ] && cp -fL /system/bin/mksh "$bbdir/sh" 2>/dev/null; then
        chmod 755 "$bbdir/sh" 2>/dev/null
    elif [ -e /system/bin/sh ] && cp -fL /system/bin/sh "$bbdir/sh" 2>/dev/null; then
        chmod 755 "$bbdir/sh" 2>/dev/null
    fi
}
provision_fallback_tools 2>/dev/null || true

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

# v5.20: 兼容性环境快照 —— root 方案(KernelSU/SukiSU/KSU-Next/APatch/Magisk)、busybox、
# SoC 厂商、Android 版本、关键命令 PATH 审计 → run/root_env.json(自检/WebUI 读);
# run/webui_url = http://127.0.0.1:8444(Magisk 没有模块 WebUI: 用浏览器打开, 以登录
# 密码/配对码登录)。热点接口缓存开机作废, 由 watchdog 首轮重新探测。
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

# pidfile_live_pid / prune_duplicate_hotspotd: v5.33 起在 bin/hnc_proc.sh(pidfile_live_pid /
# prune_duplicate_hotspotd), 与 watchdog.sh 共用一份。

# watchdogfix-v6.1: process matching must not depend on ps showing full paths.
# On ColorOS/SukiSU, ps may show only basename ("hnc_watchdog"/"hnc_launcher"),
# while cmdline/proc still belongs to HNC. The old full-path grep made sentinel
# think watchdog/launcher were dead and relaunch new copies every 30s.
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
    # v5.28 A3: 先认 run/watchdog.pid + /proc/<pid>/cmdline(不依赖 ps 输出格式,
    # ColorOS 的 ps 只显示短名字曾让哨兵每 30 秒误拉一个新 watchdog)。
    # pidfile 指向的 pid 被复用成别的进程 → pid_matches 不命中 → 判死走兜底。
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
        keep=$(echo "$pids" | tr ' ' '\n' | awk 'NF' | sort -n | head -1)
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
    local self pids p
    self=$$
    pids=$(ps -ef 2>/dev/null | awk -v self="$self" '
        $0 !~ /awk/ && $0 ~ /(hotspot_network_control|\/data\/adb\/hnc)\/service\.sh/ && $2 != self { print $2 }
    ')
    [ -z "$pids" ] && return 0
    log "watchdogfix-v6.1: stopping stale service/sentinel pids: $pids"
    for p in $pids; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    sleep 0.3 2>/dev/null || sleep 1
    for p in $pids; do
        if is_pid_alive "$p"; then
            kill -9 "$p" 2>/dev/null || true
            log "watchdogfix-v6.1: KILL stale service/sentinel pid=$p"
        fi
    done
    rm -f "$RUN/sentinel.pid" 2>/dev/null || true
}

# dpid 守护(v5.30 迁移 M5, v5.33 起只剩这一种): 开机只测 C launcher, 能用就
# 用它管 dpid, 不能用就 direct; 哨兵不判 dpid / launcher —— Go 看门狗盯 launcher,
# 「launcher 坏了 → 直拉 dpid」的救命路径也在看门狗(src/dpid/cmd/hnc_watchdog/m5.go)。
# v5.29 的 shell guard / Go supervisor 与开关 run/wd_m5.disabled 已删。

# Kill old buggy sentinel/service shells before this fixed service starts supervisors.
# Old sentinels can keep spawning watchdogs while the new service is starting.
prune_stale_service_sentinels

log "=== HNC Service Starting ==="
log "Android $(getprop ro.build.version.release) / $(getprop ro.product.brand) $(getprop ro.product.model)"

# hotfix17.3: service start must refresh runtime copy from module files —— 手动重启服务
# (WebUI「重启后端」直接 fork 本脚本)不经 post-fs-data, 运行目录可能还是旧 hnc_httpd。
# v5.33: 同步本身只有 bin/hnc_runtime_sync.sh 一份(post-fs-data.sh 也调它)。

# v5.29 T3: 升级快照 + 钉住检查。真正的快照点在 post-fs-data.sh(它每次开机
# 都比这里先把模块文件拷进运行目录); 这里再调一次只为两件事: WebUI「重启
# 后端」直接 fork 本脚本、不经 post-fs-data.sh; 以及钉住时(rc=3)跳过同步,
# 否则坏版本又被拷回来。同版本重复调用是空操作。失败(其他非 0)照常同步。
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

# v6.x 升级迁移: nDPI 实验(hnc_ndpi_probe / ndpi_*.sh / ndpi-lab.html)已整体移除,
# 旧版本机上会残留: 可能仍在跑的 ndpi_continuous.sh 常驻循环 + 其 probe 子进程、
# 运行期输出(ip_to_host.json 等)、默认配置、以及 cp -rf 不会删除的旧脚本/二进制。
# 这里一次性清掉。幂等: 文件不存在时每一步都是 no-op, 可每次开机都跑。
# 必须在 watchdog 启动之前: 旧 hnc_watchdog 读 dpi_ndpi_config.json 决定是否拉起
# ndpi_continuous.sh —— 配置删了它就不会再拉。
migrate_remove_ndpi() {
    _np=$(cat "$RUN/ndpi_continuous.pid" 2>/dev/null)
    case "$_np" in
        ''|*[!0-9]*) _np="" ;;
    esac
    # 只杀确实是 ndpi_continuous 的进程(pid 可能已被复用)
    if [ -n "$_np" ] && kill -0 "$_np" 2>/dev/null \
       && grep -q "ndpi_continuous" "/proc/$_np/cmdline" 2>/dev/null; then
        kill "$_np" 2>/dev/null
        sleep 1
        kill -9 "$_np" 2>/dev/null
        log "migrate: stopped legacy ndpi_continuous.sh pid=$_np"
    fi
    # probe 子进程(ndpi_continuous 的 trap 正常会杀, 这里兜底 SIGKILL 场景)
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
    # 同批移除的 v5.2 shadow/灰度统计脚本与其运行期开关(stats_sample.sh 已不再读)
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

# hotfix13: record platform/kernel capability profile for diagnostics and UI fallback hints
# v5.20.1: -f 而非 -x(cp 丢执行位时也要跑; 用 sh 调用不需要 x 位); 探针内部先写基础能力,
# 低延迟 qdisc 模块加载带总超时后再补写, 开机很快就有 run/capabilities.json。
if [ -f $HNC_DIR/bin/capability_probe.sh ]; then
    ( HNC="$HNC_DIR" sh $HNC_DIR/bin/capability_probe.sh >> $HNC_DIR/logs/capabilities.log 2>&1 ) &
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
#     3. 启动 watchdog(它是唯一的状态机,负责探测 + init + 守护 httpd)
#   service.sh 绝不碰 wlan0。

log "v4.0.0-patch1.5 Defer Init: iface detection + tc/iptables init delegated to watchdog"

# v5.0: httpd 永远启动(至少 loopback), 本机 WebUI 依赖它。v5.33: 远程端口
# (:8443 / :8080)由 httpd 自己按 remote_enabled 开关(remote_listener.go), 这里不再
# 读 remote_enabled, 也不再写没人读的 run/httpd.wanted。

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
        # v5.9.0: 原来这里是裸 `sed -i` 直改 rules.json —— 绕开 json.lock,
        # 与同期任何 json_set.sh/hnc_json 写者(WebUI 操作、watchdog top 写)
        # 并发时是经典 lost-update。改走 json_set.sh(与全部写者共用锁;
        # json_set.sh 先认 $HNC、没设再认 $HNC_DIR(v5.33),true 会被自动推断为 JSON bool)。
        JSON_SET="$MODDIR/bin/json_set.sh"
        [ -f "$JSON_SET" ] || JSON_SET="$HNC_DIR/bin/json_set.sh"
        if HNC=$HNC_DIR sh "$JSON_SET" top auth_required true >/dev/null 2>&1; then
            log "auth_required migrated to true via json_set.sh (locked writer)"
        else
            # 失败也无妨 - 后端反正不看这字段了, 只是 cosmetic
            log "WARN: auth_required migration via json_set.sh failed rc=$? (cosmetic only)"
        fi
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
    # v5.8.8 (audit): urandom 不可读时,不再退到 date+$$+RANDOM 弱熵(mksh RANDOM 仅
    # 15bit,本机低信任 App 可暴力构造 X-HNC-Local-Admin)。改用内核 CSPRNG
    # /proc/sys/kernel/random/uuid(get_random_bytes,每个 128bit)拼 3 个取 64 hex;
    # 仍失败则放弃生成 —— middleware 对 loopback 写接口本就 fail-closed,宁可本机管理面
    # 退回 cookie 鉴权,也不下发弱 secret。
    if [ -z "$SECRET_VAL" ] && [ -r /proc/sys/kernel/random/uuid ]; then
        SECRET_VAL=$( { cat /proc/sys/kernel/random/uuid /proc/sys/kernel/random/uuid \
                            /proc/sys/kernel/random/uuid 2>/dev/null; } | tr -dc '0-9a-f' | cut -c1-64 )
        [ "${#SECRET_VAL}" -eq 64 ] || SECRET_VAL=""
    fi
    if [ -n "$SECRET_VAL" ]; then
        # rc30.12.16 P2-1: umask 改用子 shell 隔离, 避免污染后续脚本.
        # 之前 `umask 077` 后没恢复, 后续 `>` 创建的文件都会被收紧权限.
        ( umask 077; printf "%s" "$SECRET_VAL" > "$LOCAL_ADMIN_SECRET" )
        chmod 600 "$LOCAL_ADMIN_SECRET" 2>/dev/null
        chown root:root "$LOCAL_ADMIN_SECRET" 2>/dev/null
        log "rc30.12.14: generated local admin secret ($LOCAL_ADMIN_SECRET, mode 0600)"
    else
        log "v5.8.8: WARN no CSPRNG available, NOT generating local_admin.secret — loopback write/sensitive paths stay fail-closed (cookie required), no weak-entropy fallback"
    fi
fi

# ─── 拉起 hotspotd(硬件加速兜底 + 控制接口)───────────────────
# v5.33: 设备发现只有 Go 看门狗一份(写 data/devices.json); device_detect.sh daemon
# 只负责拉起 hotspotd, 不再有 shell 轮询兜底, 也不再写 run/detect.pid。
# hotspotd 没起来不影响设备列表, 看门狗每轮会再拉。
log "Starting hotspotd (offload + control socket; device discovery is the Go watchdog's)..."
rm -f "$RUN/detect.pid" 2>/dev/null
sh $HNC_DIR/bin/device_detect.sh daemon >> $HNC_DIR/logs/detect.log 2>&1 &
# hotfix10 S11: 最多等 5s,每 100ms poll 一次 hotspotd.pid。
HPID=""
i=0
while [ $i -lt 50 ]; do
    HPID=$(pidfile_live_pid $RUN/hotspotd.pid hotspotd)
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
# data/webui_access.json 不存在时 mode=all, 只拒蜂窝上行口; allowlist / local_only
# 时非白名单客户端在 INPUT 直接 RST。幂等, watchdog 全量恢复时会再跑一次自愈。
if [ -f "$HNC_DIR/bin/webui_guard.sh" ]; then
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$HNC_DIR/logs/service.log" 2>&1 \
        || log "v5.22: WARN webui_guard apply failed (HTTP-level guard in hnc_httpd still active)"
fi

# ─── rc30.12: shell pre-launch hnc_httpd ─────────────────────
# 跟 rc30.11 区别: 不再 pre-launch supervisor (C launcher 替代了那个角色,
# 在下面 DPID launcher 块里启动). 只 pre-launch httpd, 因为 httpd 需要
# 在 watchdog 起来之前就 ready, 不然 watchdog 检测到 httpd 不在会尝试
# fork (在 ColorOS 16 上失败).

# v5.33: httpd 的启动参数只有一套, 与 Go 看门狗重拉时相同(hnc_watchdog main.go
# httpdDaemon: 只有 -hnc-dir)。远程端口(:8443 / :8080)由 httpd 自己按 rules.json 的
# remote_enabled 开关(remote_listener.go)。之前这里按 remote_enabled 决定带不带
# `-bind 0.0.0.0`, 而看门狗重拉时不带 —— httpd 崩一次远程访问就没了; 设置页切开关
# 也要等 httpd 下次重启才生效。
launch_httpd_safe() {
    nohup "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" -hnc-dir "$HNC_DIR" \
        >> "$HNC_DIR/logs/httpd.log" 2>&1 &
    echo $! > "$RUN/httpd.pid" 2>/dev/null || true
    log "launch_httpd_safe: hnc_httpd started (PID=$!; remote port follows remote_enabled)"
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
        # rc30.1: prefer Go hnc_watchdog binary over the shell main loop.
        # The Go binary uses watchdog.sh in "action" mode for business logic
        # but runs the supervision loop itself, immune to PATH/namespace
        # issues that wedged the shell loop in post-fs-data context.
        if [ -x "$HNC_DIR/bin/hnc_watchdog" ]; then
            nohup "$HNC_DIR/bin/hnc_watchdog" >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid"
            log "watchdog (Go, rc30.1+) started (PID=$(cat $RUN/watchdog.pid 2>/dev/null))"
        else
            # v5.26 T1: watchdog.sh 的 shell 主循环已删除, 不再兜底启动。
            log "FATAL: bin/hnc_watchdog missing, watchdog not started"
        fi
    fi
fi

# ─── v5.18: tether offload 旁路兜底(clsact_bpf_mode: auto 默认 / on / off) ───
# 检测 / 兜底 / clsact 闸门在 bin/hnc_offload_guard.sh(单次子命令), 由 Go 看门狗
# (offload_sched.go)按 plan 的节拍调度、on 模式下每 10 秒查一次 clsact。v5.33 删掉了
# 这里拉起的两个 shell 常驻循环(offload guard daemon / hnc_clsact_watchdog.sh)和
# 开关 run/wd_m3.disabled、run/offload_guard.owner —— v5.29 起默认就不走它们。

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
    for MAC in $(grep -oE '"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"[^}]*"limit_enabled"[[:space:]]*:[[:space:]]*true' "$RULES" \
                 | grep -oE '^"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}"' \
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
HOTSPOT_AUTO=$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_auto 2>/dev/null \
    || grep -o '"hotspot_auto"[[:space:]]*:[[:space:]]*[a-z]*' $HNC_DIR/data/rules.json 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')

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
# rc30.12: C launcher 管 dpid(Go 进程起子进程在 ColorOS 16 / SukiSU 上会被拦,
# 报 EPERM; C fork+execv 同一环境正常)。v5.33 起不再有 shell guard / Go supervisor。
DPID_LAUNCHER_C="$HNC_DIR/bin/hnc_launcher"
FORK_PROBE="$HNC_DIR/bin/fork_probe"
DPID_LAUNCHER="$DPID_BIN"
DPID_CONFIG="$HNC_DIR/etc/dpi_config.json"
DPID_PID="$RUN/dpid.pid"
DPID_GUARD_PID="$RUN/dpid_guard.pid"

find_live_dpid_guard_pid() {
    ps -ef 2>/dev/null | grep -E '[h]nc_launcher' | awk 'NR==1{print $2}'
}

# rc30.12 launcher 探测: 用 fork_probe 测 C fork+execv 能不能跑, 再真跑一下
# hnc_launcher --version(防二进制本身坏了)。能用 → C launcher 管 dpid;
# 不能用 → direct(Go 看门狗直接盯 hnc_dpid)。
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
        log "dpid launcher: fork_probe FAIL on this device"
    fi
fi

if [ -z "$LAUNCHER_CHOICE" ]; then
    log "dpid launcher: C launcher unavailable, direct mode (Go watchdog supervises hnc_dpid)"
fi

# v5.26 T2: 把选定的 dpid 守护方式原子写入 run/dpid_launcher.choice。
# Go 看门狗只认这一份(launcher | direct)。
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
    # 软迁: 把模块内默认 dpi_config.json 复制到 etc/ (如果用户没有自定义)
    mkdir -p "$HNC_DIR/etc" 2>/dev/null || true
    chmod 755 "$HNC_DIR/etc" 2>/dev/null || true   # v5.9.3 BUG-009:dpi_config.json 只读配置

    # v5.7.0-rc6: self-capture 常驻. 自动识别飞轮(per-uid 采样 + 自接口 SNI 抓取)
    # 全靠 self_capture.enabled 这个 flag; 之前默认关, 用户不点开关就永远没数据.
    # 这里在每次启动确保 flag 存在 = 默认常驻开. 用户仍可在 WebUI 临时关 (删 flag),
    # 但重启后回到常驻开. dpid 每 5s 读这个 flag, ~5s 内生效.
    if [ ! -f "$RUN/self_capture.enabled" ]; then
        : > "$RUN/self_capture.enabled" 2>/dev/null && chmod 644 "$RUN/self_capture.enabled" 2>/dev/null
        log "dpid: self-capture 常驻 — created $RUN/self_capture.enabled (default-on)"
    fi

    if [ ! -f "$DPID_CONFIG" ] && [ -f "$MODDIR/data/dpi_config.json" ]; then
        cp -f "$MODDIR/data/dpi_config.json" "$DPID_CONFIG" 2>/dev/null
        chmod 644 "$DPID_CONFIG" 2>/dev/null
        log "dpid: installed default dpi_config.json to $DPID_CONFIG"
    fi
    # v5.33: 删掉单文件规则 etc/dpi_rules.json 的安装 / 按版本升级(rc20.1 / rc29.3 起)。
    # 它是 data/dpi_rules.d/ 的逐字节派生副本, dpid 自 rc30.12.31 起有规则目录就不读它;
    # 旧装机留下的那份由 post-fs-data 清掉。规则唯一来源 = 下面同步的 dpi_rules.d/。
    # rc30.12.31 (TASK-a Stage 2): sync dpi_rules.d/ subset directory if the
    # module ships one. dpid reads etc/dpi_rules.d/*.json (globbed + merged).
    # v5.27 T1: 同步逻辑搬到 bin/dpi_rules_sync.sh。旧做法每次开机 rm -rf 再复制、
    # 只保留 99-user-custom.json, 把 _auto_expanded / _auto_promoted(学到的规则)
    # 和 97-online-update.json(在线更新)一起删了。现在保留 99 与所有 _*.json,
    # 97 只在模块版本没变时保留; 失败只记日志, 不阻断开机。
    MOD_RULES_D="$MODDIR/data/dpi_rules.d"
    DPID_RULES_D="$HNC_DIR/etc/dpi_rules.d"
    if [ -d "$MOD_RULES_D" ]; then
        _RSYNC="$MODDIR/bin/dpi_rules_sync.sh"
        [ -f "$_RSYNC" ] || _RSYNC="$HNC_DIR/bin/dpi_rules_sync.sh"
        if [ -f "$_RSYNC" ] && sh "$_RSYNC" "$MOD_RULES_D" "$DPID_RULES_D" "$MODDIR/module.prop" >> $LOG 2>&1; then
            log "dpid: synced dpi_rules.d/ ($(find "$DPID_RULES_D" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l) subset files) to $DPID_RULES_D"
        else
            log "dpid: WARN dpi_rules.d sync failed (see logs/dpi_rules_sync.log); keeping existing $DPID_RULES_D"
        fi
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
    # updates.
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

    # rc14: C launcher 用独立的 dpid_guard.pid 防重复(launcher 自己也维护它);
    # dpid.pid 只给真实 hnc_dpid 用。没有可用的 launcher 才 direct 直启 hnc_dpid。
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
# 收窄后 sentinel 的职责(v5.30 M5 起, 「launcher 坏了 → 直拉 dpid」的救命路径
# 搬进了 Go 看门狗 m5.go, 哨兵不再判 dpid / launcher):
#   - hnc_watchdog 健康 (watchdog 死了 sentinel 重启它, watchdog 自己接管
#     hotspotd / httpd / dpid)
#   - 升级观察期(v5.29 自动回滚)
#
# 委托给 watchdog 不再 sentinel 检查的:
#   - hnc_httpd  (watchdog.sh ensure_httpd_running)
#   - hotspotd   (watchdog.sh check_services)
(
    sleep 15
    log "sentinel: starting (launcher_choice=$LAUNCHER_CHOICE, dpid_launcher=$DPID_LAUNCHER, scope=watchdog(+rollback); dpid->launcher+go-watchdog)"

    while true; do
        # 哨兵不判 dpid / launcher(v5.30 M5 起): C launcher 管 dpid, Go 看门狗盯
        # launcher, 「launcher 坏了 → 直拉 dpid」的救命路径也在看门狗(m5.go)。

        # 2. hnc_watchdog 检查 (新核心职责 — watchdog 死了 sentinel 重启它)
        # rc30.12.29 (P1.7): watchdog 是 hotspotd / httpd / dpid (常规路径) 的 supervisor,
        # 它死了 sentinel 必须兜底重启. 重启后 watchdog 自己会拉起 hotspotd / httpd,
        # sentinel 不再直接管这两个 (之前的重复检查已删, 避免双 supervisor 并发拉起).
        prune_duplicate_watchdogs "sentinel-loop"
        if ! find_live_watchdog_pid >/dev/null 2>&1; then
            log "sentinel: hnc_watchdog not running, relaunching"
            nohup "$HNC_DIR/bin/hnc_watchdog" \
                >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            echo $! > "$RUN/watchdog.pid" 2>/dev/null || true
            sleep 2
        fi

        # rc30.12.29 (P1.7): hnc_httpd / hotspotd 的检查已移除 — 委托给 watchdog.
        # 之前的 sentinel 在这里直接 launch_httpd_safe / nohup hotspotd, 跟 watchdog
        # ensure_httpd_running / check_services 并发, 触发过双进程事故.

        # v5.29 T3: 升级观察期(哨兵是 shell, 不依赖新版 Go 二进制能不能跑)。
        # snapshot 建了 data/rollback.observing 才有一轮; observe 自己判窗口
        # (10 分钟)与触发条件(连续 6 败 / 崩溃重启 ≥ 5 → 恢复 .prev + 钉住)。
        if [ -f "$HNC_DIR/data/rollback.observing" ] && [ -f "$HNC_DIR/bin/hnc_rollback.sh" ]; then
            HNC_RB_LOG="$HNC_DIR/logs/rollback.log" sh "$HNC_DIR/bin/hnc_rollback.sh" observe "$HNC_DIR"
        fi

        sleep 30
    done
) >> "$HNC_DIR/logs/sentinel.log" 2>&1 &
echo $! > "$RUN/sentinel.pid" 2>/dev/null || true
log "sentinel started (PID=$(cat "$RUN/sentinel.pid" 2>/dev/null), dpid_launcher=$DPID_LAUNCHER, scope=watchdog+rollback, watchdogfix-v6.1)"
