#!/system/bin/sh
# service.sh — Magisk late_start service
# 在系统完全启动后执行,可访问所有系统服务

umask 022

MODDIR=${0%/*}
HNC_DIR=/data/local/hnc
LOG=$HNC_DIR/logs/service.log
RUN=$HNC_DIR/run
RUN_DIR=$RUN
DATA_DIR=$HNC_DIR/data

_he_loaded=0
for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh" "${0%/*}/hnc_env.sh"; do
    case "$_he" in /bin/hnc_env.sh) continue ;; esac
    if [ -f "$_he" ]; then . "$_he"; _he_loaded=1; break; fi
done
if [ "$_he_loaded" = "0" ] && [ -z "${HNC_SKIP_PATH_HARDENING:-}" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
    export PATH="/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:${PATH:-}:/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:/data/local/hnc/bin"
fi
unset _he _he_loaded

# v5.28 A3: 哨兵的进程判活改读 /proc/<pid>/cmdline(不再依赖 ps 的输出格式,
# ColorOS 的 ps 只显示短名字曾造成进程风暴)。pid_matches / pidfile_pid_matches
# 定义在 bin/hnc_proc.sh; 优先用模块目录的副本, 运行目录副本兜底。
_HNC_PROC="$MODDIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] || _HNC_PROC="$HNC_DIR/bin/hnc_proc.sh"
[ -f "$_HNC_PROC" ] && . "$_HNC_PROC"
command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$$" -500 2>/dev/null || true

mkdir -p "$HNC_DIR/logs" "$RUN" "$HNC_DIR/data/self_studio" 2>/dev/null || true
chmod 700 "$HNC_DIR" "$HNC_DIR/logs" "$RUN" 2>/dev/null || true
[ -d "$HNC_DIR/data" ] && chmod 700 "$HNC_DIR/data" 2>/dev/null || true
[ -d "$HNC_DIR/data/self_studio" ] && chmod 0755 "$HNC_DIR/data/self_studio" 2>/dev/null || true

# v6.1.0-rc.4: 开机与热重启 32M tmpfs 急救清扫。
# 将历史遗留在 run/ 下的自训练样本与字典缓存安全迁往持久化 data/(或 data/self_studio/),
# 大文件(>=4MB)仅保留尾部 2MB, 随后立即删除 run/ 下原文件及全部 *.tmp* 孤儿文件。
_hnc_rescue_run_tmpfs() {
    _rr_dir="${1:-$RUN_DIR}"
    [ -d "$_rr_dir" ] || return 0
    mkdir -p "$HNC_DIR/data/self_studio" 2>/dev/null || true
    chmod 0755 "$HNC_DIR/data/self_studio" 2>/dev/null || true
    for _rf in "$_rr_dir"/self_attrib.* "$_rr_dir"/label_samples.* "$_rr_dir"/self_fg.* \
               "$_rr_dir"/fg_timeline.* "$_rr_dir"/apk_domains.json "$_rr_dir"/app_labels_live.json; do
        [ -f "$_rf" ] || continue
        _bn=${_rf##*/}
        case "$_bn" in
            *.enabled|*.poke|*.pid|*.lock) continue ;;
            *.tmp*) rm -f "$_rf" 2>/dev/null || true; continue ;;
        esac
        case "$_bn" in
            self_attrib.*|label_samples.*|self_fg.*)
                _dst="$HNC_DIR/data/self_studio/$_bn"
                ;;
            *)
                _dst="$HNC_DIR/data/$_bn"
                ;;
        esac
        if [ ! -e "$HNC_DIR/data/self_studio/$_bn" ] && [ ! -e "$HNC_DIR/data/$_bn" ] && [ -s "$_rf" ]; then
            _sz=$(stat -c %s "$_rf" 2>/dev/null | tr -dc '0-9')
            [ -n "$_sz" ] || _sz=$(wc -c < "$_rf" 2>/dev/null | tr -dc '0-9')
            _sz=${_sz:-0}
            _dtmp="${_dst}.tmp.$$"
            if awk 'BEGIN { exit !((ARGV[1] + 0) < 4194304) }' "$_sz" 2>/dev/null; then
                if cp -f "$_rf" "$_dtmp" 2>/dev/null && [ -s "$_dtmp" ]; then
                    mv -f "$_dtmp" "$_dst" 2>/dev/null || rm -f "$_dtmp" 2>/dev/null || true
                else
                    rm -f "$_dtmp" 2>/dev/null || true
                fi
            else
                if tail -c 2097152 "$_rf" > "$_dtmp" 2>/dev/null && [ -s "$_dtmp" ]; then
                    mv -f "$_dtmp" "$_dst" 2>/dev/null || rm -f "$_dtmp" 2>/dev/null || true
                else
                    rm -f "$_dtmp" 2>/dev/null || true
                fi
            fi
            [ -f "$_dst" ] && chmod 0644 "$_dst" 2>/dev/null || true
        fi
        rm -f "$_rf" 2>/dev/null || true
    done
    rm -f "$_rr_dir"/*.tmp* "$_rr_dir"/.*.tmp* "$_rr_dir"/.*.hnc_json* "$_rr_dir"/hnc_json_literal.* 2>/dev/null || true
    unset _rr_dir _rf _bn _dst _sz _dtmp
}

# v6.0.0 Vector: 将 /data/local/hnc/run 挂载为 32M 内存 tmpfs (mode=0700),
# 令 shm_vector.bin 双槽 seqlock 共享内存与高频运行态快照 100% 驻留 RAM, 实现手机 UFS 闪存零擦写寿命损耗。
if { [ -z "$HNC_TEST_MODE" ] && [ "$RUN" = "/data/local/hnc/run" ]; } || [ "${HNC_TEST_TMPFS_FALLBACK:-0}" = "1" ]; then
    if grep -q " $RUN tmpfs " /proc/mounts 2>/dev/null; then
        rm -f "$RUN/tmpfs_unavailable" 2>/dev/null || true
    else
        _hnc_rescue_run_tmpfs "$RUN_DIR"
        _live_daemon=0
        if command -v pidfile_pid_matches >/dev/null 2>&1; then
            for _pair in "httpd.pid:hnc_httpd" "watchdog.pid:hnc_watchdog" \
                         "dpid_guard.pid:hnc_launcher" "launcher.pid:hnc_launcher" \
                         "dpid.pid:hnc_dpid" "dpid.child.pid:hnc_dpid" \
                         "hotspotd.pid:hotspotd"; do
                _pf_n=${_pair%%:*}
                _kw_n=${_pair#*:}
                if [ -f "$RUN/$_pf_n" ] && pidfile_pid_matches "$RUN/$_pf_n" "$_kw_n"; then
                    _live_daemon=1
                    break
                fi
            done
            unset _pair _pf_n _kw_n
        fi
        if [ "$_live_daemon" -eq 0 ] && command -v pid_matches >/dev/null 2>&1; then
            _early_proot="${HNC_PROC_ROOT:-/proc}"
            if [ "$_early_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ] && [ "${HNC_TEST_TMPFS_FALLBACK:-0}" != "1" ]; }; then
                for _ed in "$_early_proot"/[0-9]*; do
                    [ -r "$_ed/cmdline" ] || continue
                    _ep=${_ed##*/}
                    for _ekw in hnc_httpd hnc_watchdog hnc_launcher hnc_dpid hotspotd; do
                        if pid_matches "$_ep" "$_ekw"; then
                            _live_daemon=1
                            break 2
                        fi
                    done
                done
            fi
            unset _early_proot _ed _ep _ekw
        fi
        if [ "$_live_daemon" -eq 0 ]; then
            if [ "${HNC_TEST_TMPFS_FALLBACK:-0}" != "1" ]; then
                mount -t tmpfs -o size=32M,mode=0700,nosuid,nodev tmpfs "$RUN" 2>/dev/null || true
            fi
            if grep -q " $RUN tmpfs " /proc/mounts 2>/dev/null; then
                rm -f "$RUN/tmpfs_unavailable" 2>/dev/null || true
            else
                # tmpfs 挂载失败退回普通目录: 清空跨重启残留的运行态与锁目录并记标记
                rm -rf "$RUN/app_limits.devs" "$RUN"/offload_guard.* "$RUN/mtk_hwnat.state" \
                       "$RUN/clsact.state" "$RUN"/*.lock "$RUN/daemon.spawn" 2>/dev/null || true
                printf 'tmpfs mount failed at %s\n' "$(date +%s 2>/dev/null || echo 0)" > "$RUN/tmpfs_unavailable" 2>/dev/null \
                    || : > "$RUN/tmpfs_unavailable" 2>/dev/null || true
                chmod 644 "$RUN/tmpfs_unavailable" 2>/dev/null || true
            fi
        fi
        unset _live_daemon
    fi
fi
# 紧跟 mount -t tmpfs 之后(无论本次新挂载还是热重启已挂载), 确保 data/self_studio 就绪且 32M tmpfs 干净宽裕
_hnc_rescue_run_tmpfs "$RUN_DIR"
# P0-01: 若持久化 data/orig_tether_offload_disabled 存在(上次压制态重启), 镜像回新 tmpfs 的 run/orig_tether_offload_disabled,
# 使 hnc_watchdog (offload_sched.go:95) 即使在关热点 StateIdle 下也能感知待还原标记并立即恢复用户原设置!
if [ -s "$DATA_DIR/orig_tether_offload_disabled" ] && [ ! -f "$RUN/orig_tether_offload_disabled" ]; then
    cp -f "$DATA_DIR/orig_tether_offload_disabled" "$RUN/orig_tether_offload_disabled.tmp.$$" 2>/dev/null \
        && mv -f "$RUN/orig_tether_offload_disabled.tmp.$$" "$RUN/orig_tether_offload_disabled" 2>/dev/null \
        || rm -f "$RUN/orig_tether_offload_disabled.tmp.$$" 2>/dev/null || true
fi

# v5.9.3 BUG-009:run/ 下有 local_admin.secret(middleware 认它就给 root 级
# 写 API)。secret 文件本身早已是 0600,但目录 0777 且无 sticky 位时,别人
# 可以直接 unlink 掉它再写一个自己的 —— 收目录才是真正的修法。
chmod 700 "$HNC_DIR" "$HNC_DIR/logs" "$RUN" 2>/dev/null
[ -d "$HNC_DIR/data" ] && chmod 700 "$HNC_DIR/data" 2>/dev/null
[ -d "$HNC_DIR/data/self_studio" ] && chmod 0755 "$HNC_DIR/data/self_studio" 2>/dev/null || true
# hotfix16.4 + v6.0 重启即焚: 清理陈旧的上行降级标记及运行态敏感瞬态文件(leakguard_events.json);
# C002: shm_vector.bin 仅在 hnc_dpid 未存活时删除, 防止热唤醒 unlink 掉存活 dpid 的活跃共享内存目录项!
rm -f "$RUN/uplink_unsupported" "$RUN/uplink_fail_count" "$RUN/uplink_unsupported_logged" \
      "$RUN_DIR/leakguard_events.json" 2>/dev/null || true
_dpid_live_early=0
if command -v pidfile_pid_matches >/dev/null 2>&1; then
    pidfile_pid_matches "$RUN_DIR/dpid.pid" hnc_dpid && _dpid_live_early=1
    [ "$_dpid_live_early" -eq 0 ] && pidfile_pid_matches "$RUN_DIR/dpid.child.pid" hnc_dpid && _dpid_live_early=1
fi
if [ "$_dpid_live_early" -eq 0 ] && command -v pid_matches >/dev/null 2>&1; then
    _dp_proot="${HNC_PROC_ROOT:-/proc}"
    if [ "$_dp_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
        for _dd in "$_dp_proot"/[0-9]*; do
            [ -r "$_dd/cmdline" ] || continue
            if pid_matches "${_dd##*/}" hnc_dpid; then
                _dpid_live_early=1
                break
            fi
        done
    fi
    unset _dp_proot _dd
fi
[ "$_dpid_live_early" -eq 0 ] && rm -f "$RUN_DIR/shm_vector.bin" 2>/dev/null || true
unset _dpid_live_early

provision_fallback_tools() {
    if ! command -v hnc_provision_fallback_tools >/dev/null 2>&1; then
        for _he in "${MODDIR:-}/bin/hnc_env.sh" "$HNC_DIR/bin/hnc_env.sh"; do
            case "$_he" in /bin/hnc_env.sh) continue ;; esac
            if [ -f "$_he" ]; then . "$_he"; break; fi
        done
        unset _he
    fi
    if command -v hnc_provision_fallback_tools >/dev/null 2>&1; then
        hnc_provision_fallback_tools "$HNC_DIR" "$MODDIR"
    fi
}
provision_fallback_tools 2>/dev/null || true

# 记下自己路径让 cleanup.sh restart 时能找到我们
echo "$MODDIR" > "$RUN/service.path" 2>/dev/null

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HNC] $1" >> "$LOG"
}

_HNC_SVC_VER=""
for _mp in "$MODDIR/module.prop" "$HNC_DIR/module.prop" "/data/adb/modules/hotspot_net_ctl/module.prop"; do
    [ -f "$_mp" ] || continue
    _HNC_SVC_VER=$(sed -n '/^version=/{s/^version=//p;q;}' "$_mp" 2>/dev/null | tr -d ' \t\r\n"')
    [ -n "$_HNC_SVC_VER" ] && break
done
unset _mp

# 兼容性环境快照
_HNC_COMPAT="$MODDIR/bin/hnc_compat.sh"
[ -f "$_HNC_COMPAT" ] || _HNC_COMPAT="$HNC_DIR/bin/hnc_compat.sh"
if [ -f "$_HNC_COMPAT" ]; then
    HNC_DIR="$HNC_DIR" sh "$_HNC_COMPAT" root >/dev/null 2>&1 || true
    log "compat: $(tr -d '\n' < "$RUN/root_env.json" 2>/dev/null | cut -c1-400)"
    case "$(cat "$RUN/root_env.json" 2>/dev/null)" in
        *'"module_webui":false'*) log "compat: 当前 root 方案无模块 WebUI, 请用浏览器打开 $(cat "$RUN/webui_url" 2>/dev/null)" ;;
    esac
fi
rm -f "$RUN/iface_detect.json" 2>/dev/null

is_pid_alive() {
    [ -n "$1" ] && kill -0 "$1" 2>/dev/null
}

process_by_name_alive() {
    local n _proot _d _p
    n="$1"
    [ -z "$n" ] && return 1
    _proot="${HNC_PROC_ROOT:-/proc}"
    if command -v pid_matches >/dev/null 2>&1; then
        for _d in "$_proot"/[0-9]*; do
            [ -r "$_d/cmdline" ] || continue
            _p=${_d##*/}
            if pid_matches "$_p" "$n" && is_pid_alive "$_p"; then
                return 0
            fi
        done
    fi
    pidof "$n" >/dev/null 2>&1 && return 0
    return 1
}

list_watchdog_pids() {
    local _proot="${HNC_PROC_ROOT:-/proc}" _wp _d _p _cand
    (
        if command -v pidfile_live_pid >/dev/null 2>&1; then
            _wp=$(pidfile_live_pid "$RUN/watchdog.pid" hnc_watchdog 2>/dev/null)
            [ -n "$_wp" ] && echo "$_wp"
        fi
        if command -v pid_matches >/dev/null 2>&1; then
            for _d in "$_proot"/[0-9]*; do
                [ -r "$_d/cmdline" ] || continue
                _p=${_d##*/}
                pid_matches "$_p" hnc_watchdog && echo "$_p"
            done
        fi
        if [ ! -r "$_proot/self/cmdline" ] && [ ! -r "$_proot/$$/cmdline" ]; then
            for _cand in $(pidof hnc_watchdog 2>/dev/null) \
                         $(ps -A 2>/dev/null | awk '$0 !~ /awk/ && $0 !~ /grep/ && $0 ~ /(^|[ \/])hnc_watchdog([[:space:]]|$)/ { print $2 }'); do
                case "$_cand" in ''|*[!0-9]*) continue ;; esac
                if [ -r "$_proot/$_cand/cmdline" ] && command -v pid_matches >/dev/null 2>&1; then
                    pid_matches "$_cand" hnc_watchdog && echo "$_cand"
                else
                    echo "$_cand"
                fi
            done
        fi
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
    local reason pids count keep p _proot="${HNC_PROC_ROOT:-/proc}"
    reason="$1"
    if [ "$_proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 0
    fi
    pids="$(list_watchdog_pids | tr '\n' ' ')"
    count=$(echo "$pids" | wc -w | tr -d ' ')
    [ -z "$count" ] && count=0
    [ "$count" -le 1 ] && return 0

    keep=$(cat "$RUN/watchdog.pid" 2>/dev/null | tr -d ' \r\n')
    case " $pids " in
        *" $keep "*) ;;
        *) keep="" ;;
    esac
    if [ -z "$keep" ]; then
        keep=$(echo "$pids" | tr ' ' '\n' | awk 'NF' | sort -n | head -n 1)
    fi
    [ -n "$keep" ] && echo "$keep" > "$RUN/watchdog.pid" 2>/dev/null || true
    log "duplicate watchdogs detected count=$count keep=$keep reason=$reason"

    for p in $pids; do
        [ -z "$p" ] && continue
        [ "$p" = "$$" ] && continue
        [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
        [ "$p" = "$keep" ] && continue
        kill "$p" 2>/dev/null || true
    done
    sleep 0.3 2>/dev/null || sleep 1
    for p in $pids; do
        [ -z "$p" ] && continue
        [ "$p" = "$$" ] && continue
        [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
        [ "$p" = "$keep" ] && continue
        if is_pid_alive "$p"; then
            kill -9 "$p" 2>/dev/null || true
            log "KILL duplicate hnc_watchdog pid=$p keep=$keep"
        fi
    done
}

_is_exact_service_sh_pid() {
    local _sp="$1" _proot="${2:-/proc}" _a0="" _a1=""
    case "$_sp" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_sp" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_sp" = "$PPID" ] && return 1
    [ -r "$_proot/$_sp/cmdline" ] || return 1
    _a0=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '1p')
    _a1=$(tr '\000' '\n' < "$_proot/$_sp/cmdline" 2>/dev/null | sed -n '2p')
    case "$_a0" in
        */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$MODDIR/service.sh")
            return 0
            ;;
    esac
    case "${_a0##*/}" in
        sh|mksh|ash|dash|busybox)
            [ "$_a1" = "-c" ] && return 1
            case "$_a1" in
                */hotspot_net_ctl/service.sh|*/hotspot_network_control/service.sh|/data/adb/hnc/service.sh|"$MODDIR/service.sh")
                    return 0
                    ;;
            esac
            ;;
    esac
    return 1
}

prune_stale_service_sentinels() {
    local self proot old_spid pids d p
    self=$$
    proot="${HNC_PROC_ROOT:-/proc}"
    if [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; then
        if [ "$MODDIR" != "/data/adb/modules/hotspot_network_control" ] && [ -d "/data/adb/modules/hotspot_network_control" ]; then
            : > "/data/adb/modules/hotspot_network_control/disable" 2>/dev/null || true
            : > "/data/adb/modules/hotspot_network_control/remove" 2>/dev/null || true
        fi
    fi
    pids=""
    # 删除 sentinel.pid 前必须先读出旧哨兵 PID 并精确校验 argv 指向 service.sh,
    # 优雅终止后再删 pidfile, 根治重启后端时旧后台哨兵 subshell 残留堆积!
    if [ -f "$RUN/sentinel.pid" ]; then
        old_spid=$(cat "$RUN/sentinel.pid" 2>/dev/null | tr -dc '0-9')
        if [ -n "$old_spid" ] && [ "$old_spid" != "$self" ] && _is_exact_service_sh_pid "$old_spid" "$proot"; then
            pids="$old_spid"
        fi
    fi
    # 仅在真机运行环境扫描 /proc 兜底未登记在 sentinel.pid 的旧 service.sh 实例(沙箱单测绝不扫宿主机 /proc)
    if [ "$proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
        for d in "$proot"/[0-9]*; do
            [ -r "$d/cmdline" ] || continue
            p=${d##*/}
            [ "$p" = "$self" ] && continue
            if _is_exact_service_sh_pid "$p" "$proot"; then
                pids="$pids $p"
            fi
        done
    fi
    pids=$(printf '%s\n' $pids | awk 'NF && !seen[$1]++ { print $1 }' | tr '\n' ' ')
    if [ -n "$pids" ]; then
        log "stopping stale service/sentinel pids: $pids"
        for p in $pids; do
            [ -n "$p" ] && [ "$p" != "$$" ] && [ "$p" != "${PPID:-}" ] && kill "$p" 2>/dev/null || true
        done
        sleep 0.3 2>/dev/null || sleep 1
        for p in $pids; do
            [ -z "$p" ] && continue
            [ "$p" = "$$" ] && continue
            [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
            if is_pid_alive "$p"; then
                kill -9 "$p" 2>/dev/null || true
                log "KILL stale service/sentinel pid=$p"
            fi
        done
    fi
    rm -f "$RUN/sentinel.pid" 2>/dev/null || true
}

# Kill old buggy sentinel/service shells before this fixed service starts supervisors.
prune_stale_service_sentinels
echo "$$" > "$RUN/service.pid" 2>/dev/null || true
trap 'rm -f "$RUN/service.pid" 2>/dev/null || true' EXIT

log "=== HNC ${_HNC_SVC_VER:+$_HNC_SVC_VER }Service Starting ==="
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
    _np=$(cat "$RUN/ndpi_continuous.pid" 2>/dev/null | tr -dc '0-9')
    if [ -n "$_np" ] && [ "$_np" != "$$" ] && [ "$_np" != "${PPID:-}" ] && kill -0 "$_np" 2>/dev/null; then
        _na0=$(tr '\000' '\n' < "/proc/$_np/cmdline" 2>/dev/null | sed -n '1p')
        _na1=$(tr '\000' '\n' < "/proc/$_np/cmdline" 2>/dev/null | sed -n '2p')
        if [ "${_na0##*/}" = "ndpi_continuous.sh" ] || { [ "$_na1" != "-c" ] && [ "${_na1##*/}" = "ndpi_continuous.sh" ]; }; then
            kill "$_np" 2>/dev/null
            sleep 1
            kill -9 "$_np" 2>/dev/null
            log "migrate: stopped legacy ndpi_continuous.sh pid=$_np"
        fi
        unset _na0 _na1
    fi
    if [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ] && command -v pkill >/dev/null 2>&1; then
        pkill -x hnc_ndpi_probe 2>/dev/null || true
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
              "$RUN/stats_v52_rc.enabled" "$RUN/stats_v52_rc1.enabled" \
              "$HNC_DIR/bin/ahnc_migration.sh" "$HNC_DIR/bin/hnc_common.sh" \
              "$RUN/.ahnc_migration_done" "$RUN/dpid_crashflag"; do
        if [ -e "$_f" ]; then
            rm -f "$_f" 2>/dev/null && _nd_removed=$((_nd_removed + 1))
        fi
    done
    [ "$_nd_removed" -gt 0 ] && log "migrate: removed $_nd_removed legacy file(s)"
    return 0
}
if [ "$_RB" != 3 ]; then
    migrate_remove_ndpi
else
    log "rollback: version pinned, skip migrate_remove_ndpi"
fi

if [ -f "$HNC_DIR/bin/capability_probe.sh" ]; then
    ( HNC="$HNC_DIR" sh "$HNC_DIR/bin/capability_probe.sh" >> "$HNC_DIR/logs/capabilities.log" 2>&1 ) &
fi

wait_for_network() {
    local max=60
    local cnt=0
    while [ $cnt -lt $max ]; do
        if ip link show 2>/dev/null | grep -qE 'wlan|ap0|swlan|rmnet|ccmni|eth|usb'; then
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

# ─── 本机应用防火墙与本机 DNS 拦截开机早恢复(在 wait_for_network 之前落表防漏包) ──
if [ -s "$DATA_DIR/self_firewall.json" ] && [ -f "$HNC_DIR/bin/self_firewall_sync.sh" ]; then
    sh "$HNC_DIR/bin/self_firewall_sync.sh" apply >> "$HNC_DIR/logs/service.log" 2>&1 \
        && log "self_firewall: restored persisted rules from $DATA_DIR/self_firewall.json" \
        || log "WARN: self_firewall apply failed on boot (hnc_httpd will retry)"
fi

wait_for_network

log "defer-init: iface detection + tc/iptables init delegated to watchdog"

# ─── auth_required 自动迁移到默认拒绝 ────────────────
RULES_JSON="$HNC_DIR/data/rules.json"
if [ -f "$RULES_JSON" ]; then
    CUR_AUTH=$(grep -o '"auth_required"[[:space:]]*:[[:space:]]*[a-z]*' \
        "$RULES_JSON" 2>/dev/null | awk -F: '{print $2}' | tr -d ' ')
    if [ "$CUR_AUTH" = "false" ]; then
        log "migration: auth_required=false in rules.json detected, auto-upgrading to true"
        log "  (default-deny enforced regardless; keeping WebUI toggle consistent)"
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

# ─── 生成本机管理员密钥 (loopback 鉴权加固) ───────────
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
        log "generated local admin secret ($LOCAL_ADMIN_SECRET, mode 0600)"
    else
        log "WARN: no CSPRNG available, NOT generating local_admin.secret — loopback write/sensitive paths stay fail-closed (cookie required), no weak-entropy fallback"
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
_hp_keep=$(pidfile_live_pid "$RUN/hotspotd.pid" hotspotd 2>/dev/null)
[ -n "$_hp_keep" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$_hp_keep" -800 2>/dev/null || true

# ─── WebUI 访问白名单落防火墙与 PENDING 初始状态(必须在 httpd 开监听之前) ────────
if [ ! -e "$RUN/hnc_state" ]; then
    printf 'PENDING\n' > "$RUN/hnc_state.tmp.$$" 2>/dev/null \
        && mv -f "$RUN/hnc_state.tmp.$$" "$RUN/hnc_state" 2>/dev/null \
        || printf 'PENDING\n' > "$RUN/hnc_state" 2>/dev/null || true
    rm -f "$RUN/hnc_state.tmp.$$" 2>/dev/null || true
fi
if [ -f "$HNC_DIR/bin/webui_guard.sh" ]; then
    sh "$HNC_DIR/bin/webui_guard.sh" apply >> "$HNC_DIR/logs/service.log" 2>&1 \
        || log "WARN: webui_guard apply failed (HTTP-level guard in hnc_httpd still active)"
fi

# ─── shell pre-launch hnc_httpd ─────────────────────
launch_httpd_safe() {
    nohup "$HNC_DIR/daemon/hnc_httpd/hnc_httpd" -hnc-dir "$HNC_DIR" \
        >> "$HNC_DIR/logs/httpd.log" 2>&1 &
    echo $! > "$RUN/httpd.pid" 2>/dev/null || true
    log "launch_httpd_safe: hnc_httpd started (PID=$!; remote port follows remote_enabled)"
}

# 基于精确进程名/argv[0] 清理旧模块残留的重复 hnc_httpd 实例(严禁整条 cmdline *hnc_httpd* 通配)
prune_duplicate_httpds() {
    local proot="${HNC_PROC_ROOT:-/proc}"
    local keep="" d p cmd count=0 all_pids=""
    if [ "$proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 0
    fi
    keep=$(pidfile_live_pid "$RUN/httpd.pid" hnc_httpd 2>/dev/null)
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        [ "$p" = "$$" ] && continue
        [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
        pid_matches "$p" hnc_httpd || continue
        cmd=$(tr '\000' ' ' < "$d/cmdline" 2>/dev/null)
        case "$cmd" in
            *" -port "*|*" -loopback-port "*|*hotspot_network_control*)
                kill "$p" 2>/dev/null || true
                usleep 100000 2>/dev/null || sleep 1
                kill -9 "$p" 2>/dev/null || true
                log "terminated legacy hnc_httpd instance pid=$p"
                continue
                ;;
        esac
        all_pids="$all_pids $p"
        count=$((count + 1))
    done
    if [ "$count" -gt 1 ]; then
        case " $all_pids " in
            *" $keep "*) ;;
            *) keep=$(printf '%s\n' $all_pids | sort -n | head -n 1) ;;
        esac
        [ -n "$keep" ] && echo "$keep" > "$RUN/httpd.pid" 2>/dev/null || true
        for p in $all_pids; do
            [ "$p" = "$keep" ] && continue
            [ "$p" = "$$" ] && continue
            [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
            kill "$p" 2>/dev/null || true
            usleep 100000 2>/dev/null || sleep 1
            kill -9 "$p" 2>/dev/null || true
            log "terminated duplicate hnc_httpd pid=$p (kept=$keep)"
        done
    fi
}

find_live_httpd_by_proc() {
    local proot="${HNC_PROC_ROOT:-/proc}"
    local d p
    if [ "$proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 1
    fi
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
        log "pre-launch: hnc_httpd already running (PID=$HP)"
    else
        launch_httpd_safe
        sleep 1
        prune_duplicate_httpds
        HP=$(pidfile_live_pid "$RUN/httpd.pid" hnc_httpd 2>/dev/null)
    fi
    [ -n "$HP" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$HP" -800 2>/dev/null || true
fi

# ─── dpid_launcher.choice 预探测(必须在启动 hnc_watchdog 之前落盘, 防止看门狗缺省误拉 launcher) ──
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
    if [ "$proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 1
    fi
    for d in "$proot"/[0-9]*; do
        [ -r "$d/cmdline" ] || continue
        p=${d##*/}
        if pid_matches "$p" hnc_launcher; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

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
            log "dpid launcher: hnc_launcher (C) — fork_probe PASS + exec PASS"
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
_dlc_tmp="$RUN/dpid_launcher.choice.tmp.$$"
if printf '%s\n' "$_dpid_choice" > "$_dlc_tmp" 2>/dev/null && [ -s "$_dlc_tmp" ]; then
    mv -f "$_dlc_tmp" "$RUN/dpid_launcher.choice" 2>/dev/null || rm -f "$_dlc_tmp" 2>/dev/null || true
else
    rm -f "$_dlc_tmp" 2>/dev/null || true
    printf '%s\n' "$_dpid_choice" > "$RUN/dpid_launcher.choice" 2>/dev/null || true
fi
unset _dlc_tmp
log "dpid launcher choice persisted: $_dpid_choice (raw=$LAUNCHER_CHOICE)"

if [ "$_dpid_choice" = "direct" ]; then
    _res_lps=""
    for _lpf in "$DPID_GUARD_PID" "$RUN/launcher.pid"; do
        _cand_lp=$(pidfile_live_pid "$_lpf" hnc_launcher 2>/dev/null)
        [ -n "$_cand_lp" ] && _res_lps="$_res_lps $_cand_lp"
    done
    _scan_lp=$(find_live_dpid_guard_pid)
    [ -n "$_scan_lp" ] && _res_lps="$_res_lps $_scan_lp"
    _res_proot="${HNC_PROC_ROOT:-/proc}"
    if [ "$_res_proot" != "/proc" ] || { [ "${HNC_DIR:-/data/local/hnc}" = "/data/local/hnc" ] && [ -z "${HNC_TEST_MODE:-}" ]; }; then
        for _rd in "$_res_proot"/[0-9]*; do
            [ -r "$_rd/cmdline" ] || continue
            _rp=${_rd##*/}
            pid_matches "$_rp" hnc_launcher && _res_lps="$_res_lps $_rp"
        done
    fi
    _res_lps=$(printf '%s\n' $_res_lps | awk 'NF && !seen[$1]++ { print $1 }' | tr '\n' ' ')
    if [ -n "$_res_lps" ]; then
        for _lp in $_res_lps; do
            [ -n "$_lp" ] && [ "$_lp" != "$$" ] && [ "$_lp" != "${PPID:-}" ] && kill "$_lp" 2>/dev/null || true
        done
        usleep 200000 2>/dev/null || sleep 1
        for _lp in $_res_lps; do
            [ -n "$_lp" ] && [ "$_lp" != "$$" ] && [ "$_lp" != "${PPID:-}" ] || continue
            if pid_matches "$_lp" hnc_launcher && is_pid_alive "$_lp"; then
                kill -9 "$_lp" 2>/dev/null || true
            fi
        done
        rm -f "$DPID_GUARD_PID" "$RUN/launcher.pid" "$RUN/dpid.crashflag" "$RUN/dpid_crashflag" 2>/dev/null || true
        log "dpid launcher: terminated residual hnc_launcher pids=[$_res_lps] in direct mode and cleared crashflag"
    fi
    unset _res_lps _lpf _cand_lp _scan_lp _res_proot _rd _rp _lp
fi
unset _dpid_choice

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
        WPID="$LIVE_WD"
        log "watchdog live without pidfile (PID=$LIVE_WD), repaired pidfile"
    else
        rm -f "$RUN/watchdog.pid" 2>/dev/null || true
        if [ -x "$HNC_DIR/bin/hnc_watchdog" ]; then
            nohup "$HNC_DIR/bin/hnc_watchdog" >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            WPID="$!"
            echo "$WPID" > "$RUN/watchdog.pid"
            log "watchdog (Go) started (PID=$(cat "$RUN/watchdog.pid" 2>/dev/null))"
        else
            log "FATAL: bin/hnc_watchdog missing, watchdog not started"
        fi
    fi
fi
[ -n "$WPID" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$WPID" -900 2>/dev/null || true

# 启动后延迟清理一次长期未见的离线规则, 防止 rules.json 膨胀。
if [ -x "$HNC_DIR/bin/cleanup_stale_rules.sh" ]; then
    (sleep 60 && sh "$HNC_DIR/bin/cleanup_stale_rules.sh") >> "$HNC_DIR/logs/cleanup_stale.log" 2>&1 &
fi

log "=== All services started ==="
log "All services started. WebUI: open KernelSU manager -> modules -> HNC"

# ─── Offload Recovery ────────────────────────
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

# ─── hnc_dpid (DPI 被动观察 daemon) ────────────


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

    if [ "$_RB" = 3 ]; then
        log "rollback: version pinned, skip etc/ DPI rules sync (keeping existing $HNC_DIR/etc)"
    else
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
        MOD_JA4="$MODDIR/data/dpi_ja4_fingerprints.json"
        if [ ! -f "$DPID_JA4" ] && [ -f "$MOD_JA4" ]; then
            cp -f "$MOD_JA4" "$DPID_JA4" 2>/dev/null
            chmod 644 "$DPID_JA4" 2>/dev/null
            log "dpid: installed default dpi_ja4_fingerprints.json to $DPID_JA4"
        elif [ -f "$DPID_JA4" ] && [ -f "$MOD_JA4" ]; then
            MOD_JV=$(grep -m1 '"rules_version"' "$MOD_JA4" 2>/dev/null | sed 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
            ETC_JV=$(grep -m1 '"rules_version"' "$DPID_JA4" 2>/dev/null | sed 's/.*"rules_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
            if [ -n "$MOD_JV" ] && [ "$MOD_JV" != "$ETC_JV" ]; then
                JA4_BAK="$DPID_JA4.bak-$(date +%s 2>/dev/null || echo prev)"
                cp -f "$DPID_JA4" "$JA4_BAK" 2>/dev/null || true
                if cp -f "$MOD_JA4" "$DPID_JA4.tmp.$$" 2>/dev/null && mv -f "$DPID_JA4.tmp.$$" "$DPID_JA4" 2>/dev/null; then
                    chmod 644 "$DPID_JA4" 2>/dev/null
                    log "dpid: upgraded dpi_ja4_fingerprints.json: was [$ETC_JV] -> now [$MOD_JV]; backup at $JA4_BAK"
                else
                    rm -f "$DPID_JA4.tmp.$$" 2>/dev/null || true
                fi
            fi
        fi
    fi

    if [ "$DPID_LAUNCHER" != "$DPID_BIN" ]; then
        gp=$(pidfile_live_pid "$DPID_GUARD_PID" hnc_launcher)
        if [ -n "$gp" ] && kill -0 "$gp" 2>/dev/null; then
            log "hnc_dpid launcher already running (PID=$gp, choice=$LAUNCHER_CHOICE), skip duplicate launch"
        else
            live_gp=$(find_live_dpid_guard_pid)
            if [ -n "$live_gp" ] && kill -0 "$live_gp" 2>/dev/null; then
                echo "$live_gp" > "$DPID_GUARD_PID" 2>/dev/null || true
                gp="$live_gp"
                log "hnc_dpid launcher live without pidfile (PID=$live_gp, choice=$LAUNCHER_CHOICE), repaired pidfile and skipped duplicate launch"
            else
                rm -f "$DPID_GUARD_PID" 2>/dev/null || true
                log "starting hnc_dpid launcher: $DPID_LAUNCHER (choice=$LAUNCHER_CHOICE)"
                nohup "$DPID_LAUNCHER" >> "$HNC_DIR/logs/dpid_guard.log" 2>&1 &
                gp="$!"
                echo "$gp" > "$DPID_GUARD_PID"
                log "hnc_dpid launcher started (PID: $(cat "$DPID_GUARD_PID"))"
            fi
        fi
        [ -n "$gp" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$gp" -850 2>/dev/null || true
        _dp_child=$(pidfile_live_pid "$DPID_PID" hnc_dpid 2>/dev/null)
        [ -n "$_dp_child" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$_dp_child" -700 2>/dev/null || true
    else
        dp=$(pidfile_live_pid "$DPID_PID" hnc_dpid)
        if [ -n "$dp" ] && kill -0 "$dp" 2>/dev/null; then
            log "hnc_dpid already running (PID=$dp, direct mode), skip duplicate launch"
        else
            log "starting hnc_dpid direct: $DPID_BIN (no launcher available)"
            nohup "$DPID_BIN" -config "$DPID_CONFIG" >> "$HNC_DIR/logs/dpid.log" 2>&1 &
            dp="$!"
            echo "$dp" > "$DPID_PID"
            log "hnc_dpid started (PID: $(cat "$DPID_PID"))"
        fi
        [ -n "$dp" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$dp" -700 2>/dev/null || true
    fi
fi

# ─── rc30.12.16: 进程哨兵循环 ──────────────────────────────────
(
    command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$$" -850 2>/dev/null || true
    sleep 15
    [ -f "$HNC_DIR/bin/hnc_activity.sh" ] && . "$HNC_DIR/bin/hnc_activity.sh"
    log "sentinel: starting (launcher_choice=$LAUNCHER_CHOICE, dpid_launcher=$DPID_LAUNCHER, scope=watchdog(+rollback); dpid->launcher+go-watchdog)"

    while true; do
        prune_duplicate_watchdogs "sentinel-loop"
        if ! find_live_watchdog_pid >/dev/null 2>&1; then
            log "sentinel: hnc_watchdog not running, relaunching"
            nohup "$HNC_DIR/bin/hnc_watchdog" \
                >> "$HNC_DIR/logs/watchdog.log" 2>&1 &
            _new_wd="$!"
            echo "$_new_wd" > "$RUN/watchdog.pid" 2>/dev/null || true
            command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$_new_wd" -900 2>/dev/null || true
            sleep 2
        fi
        _cur_dp=$(pidfile_live_pid "$RUN/dpid.pid" hnc_dpid 2>/dev/null)
        [ -n "$_cur_dp" ] && command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$_cur_dp" -700 2>/dev/null || true

        _sent_sleep=30
        if [ -f "$HNC_DIR/data/rollback.observing" ] && [ -f "$HNC_DIR/bin/hnc_rollback.sh" ]; then
            HNC_RB_LOG="$HNC_DIR/logs/rollback.log" sh "$HNC_DIR/bin/hnc_rollback.sh" observe "$HNC_DIR"
        elif command -v hnc_act_load >/dev/null 2>&1; then
            _sent_now=$(date +%s 2>/dev/null || echo 0)
            if hnc_act_load "$_sent_now" && [ "$ACT_OK" = "1" ] && [ "$ACT_LEVEL" = "hotspot_off" ]; then
                _sent_sleep=120
            fi
        fi

        sleep "$_sent_sleep"
    done
) >> "$HNC_DIR/logs/sentinel.log" 2>&1 &
_sent_pid="$!"
echo "$_sent_pid" > "$RUN/sentinel.pid" 2>/dev/null || true
command -v hnc_protect_daemon >/dev/null 2>&1 && hnc_protect_daemon "$_sent_pid" -850 2>/dev/null || true
rm -f "$RUN/service.pid" 2>/dev/null || true
log "sentinel started (PID=$(cat "$RUN/sentinel.pid" 2>/dev/null), dpid_launcher=$DPID_LAUNCHER, scope=watchdog+rollback, ${_HNC_SVC_VER:-v6.1})"
