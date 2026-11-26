#!/system/bin/sh
# hnc_rollback.sh — v5.29 T3: 升级自检 + 自动回滚。
#
# 目标: 刷了坏包(核心进程起不来)时自动退回上一版。只看「核心进程能
# 不能起来」(httpd 活着 + 8444 在听 + watchdog 活着), 不看网络规则
# —— 网络规则会因为各种原因暂时不健康, 拿它做回滚条件会误伤。
#
# 用法(post-fs-data.sh / service.sh / 哨兵调用, 也可手工):
#   hnc_rollback.sh snapshot <moddir> <hncdir>
#       post-fs-data.sh 拷模块文件之前调(service.sh 同步前再调一次, 同版本
#       是空操作, 只为钉住时跳过同步): 模块 versionCode 与
#       data/runtime_version 不同(= 刚升级)时, 把运行目录 bin/ daemon/
#       webroot/ 打包到 .prev/(先写临时目录再整体换, 失败不影响开机),
#       开始观察期; 记录新版本。返回 3 = 已钉住(pinned), 调用方跳过同步。
#   hnc_rollback.sh observe <hncdir>
#       观察期内每 30 秒调一次(哨兵): 连续 6 次(3 分钟)核心没起来
#       (httpd 活 + 8444 在听 + watchdog 活, 任一项不满足即算这轮失败),
#       或崩溃重启合计 ≥ 5 次(首次看到的 pid 只当基线) → 恢复 .prev/ + 写 rollback.json
#       + 钉住新版本 + 重启核心进程。data/rollback.disabled 存在时只记录。
#
# 端口判定不依赖 curl/nc(手机上不保证有): 读 /proc/net/tcp{,6},
# 本地端口 20FC(8444)且状态 0A(LISTEN)。

[ -z "$HNC_SKIP_PATH_HARDENING" ] && [ -z "$HNC_TEST_MODE" ] && export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH:/data/local/hnc/bin
HNC_RB_LOG="${HNC_RB_LOG:-/dev/null}"
rb_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [rollback] $*" >> "$HNC_RB_LOG" 2>/dev/null || true; }

rb_mod_vc() { sed -n '/^versionCode=/{s/^versionCode=//p;q;}' "$1/module.prop" 2>/dev/null | tr -d ' \t\r\n'; }

# v6.1.0-alpha.1: 纯 POSIX 十进制归一化(剥离前导零 + <=9 位上限, 根除 dash/ash 八进制崩溃与 mksh 32 位溢出)
rb_norm_vc() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    _rb_vc=$1
    while [ "${_rb_vc#0}" != "$_rb_vc" ]; do
        _rb_vc=${_rb_vc#0}
    done
    [ -n "$_rb_vc" ] || _rb_vc=0
    [ "${#_rb_vc}" -le 9 ] || return 1
    return 0
}

# 判定是否为 v6+ 预发布走廊 versionCode (6009101..6009999; >=6000000 下界防 6 位历史码误判)
rb_is_prerelease_vc() {
    rb_norm_vc "$1" || return 1
    [ "$_rb_vc" -ge 6000000 ] || return 1
    _rb_rem=$(( _rb_vc % 10000 ))
    [ "$_rb_rem" -ge 9100 ] && return 0
    return 1
}

# 正向判定是否为合法正式版 versionCode (绝不用 ! rb_is_prerelease_vc 防止脏字符串取反为真)
rb_is_stable_vc() {
    rb_norm_vc "$1" || return 1
    [ "$_rb_vc" -gt 0 ] || return 1
    if [ "$_rb_vc" -ge 6000000 ]; then
        _rb_rem=$(( _rb_vc % 10000 ))
        [ "$_rb_rem" -lt 9100 ] && return 0
        return 1
    fi
    return 0
}

rb_data() { echo "$1/data"; }
rb_run() { echo "$1/run"; }

# v6.1.0-rc.10: 配置快照白名单(覆盖核心策略、本机防火墙、五大战术舱、隐私安检、随机 MAC / 访问守卫 / 自训策略及 v6_*.json; 严禁包含凭据与运行态文件)
RB_CFG_STATIC_LIST="rules.json self_firewall.json device_names.json templates.json conn_blocks.json app_limits.json limit_policies.json autorate.json alerts_config.json app_controls.json dns_takeover.json encdns.json mac_aliases.json dpi_user_rules.json phone_usage_config.json dpi_experiment.json device_ident_override.json startup_fp.json fp_prototypes.json dpi_self_config.json leakguard_config.json vector_express.json update_leash.json thermo_cruise.json rmac_policy.json webui_access.json dpi_fp_prototypes.json self_policy.json"

rb_is_cfg_whitelisted() {
    case "$1" in
        ''|*/*|*'..'*) return 1 ;;
        remote_tokens.json|devices.json|rollback.*|runtime_version*|*.jsonl) return 1 ;;
        leakguard_config.json|vector_express.json|update_leash.json|thermo_cruise.json|\
        rmac_policy.json|webui_access.json|dpi_fp_prototypes.json|self_policy.json|\
        rules.json|self_firewall.json|device_names.json|templates.json|conn_blocks.json|app_limits.json|\
        limit_policies.json|autorate.json|alerts_config.json|app_controls.json|\
        dns_takeover.json|encdns.json|mac_aliases.json|dpi_user_rules.json|\
        phone_usage_config.json|dpi_experiment.json|device_ident_override.json|\
        startup_fp.json|fp_prototypes.json|dpi_self_config.json)
            return 0 ;;
        v6_*.json)
            case "${1#v6_}" in
                ''|.json|*[!A-Za-z0-9_.-]*) return 1 ;;
                *) return 0 ;;
            esac ;;
    esac
    return 1
}

rb_pack_cfg_snapshot() {
    _src_d="$1"; _dst_c="$2"
    [ -d "$_src_d" ] || return 0
    mkdir -p "$_dst_c" 2>/dev/null || return 0
    for _cfn in $RB_CFG_STATIC_LIST; do
        [ -f "$_src_d/$_cfn" ] || continue
        rb_is_cfg_whitelisted "$_cfn" || continue
        cp -af "$_src_d/$_cfn" "$_dst_c/$_cfn" 2>/dev/null || true
        [ "$_cfn" = "self_firewall.json" ] && chmod 600 "$_dst_c/$_cfn" 2>/dev/null || true
    done
    for _v6f in "$_src_d"/v6_*.json; do
        [ -f "$_v6f" ] || continue
        _v6bn="${_v6f##*/}"
        rb_is_cfg_whitelisted "$_v6bn" || continue
        cp -af "$_v6f" "$_dst_c/$_v6bn" 2>/dev/null || true
    done
    return 0
}

rb_restore_cfg_snapshot() {
    _src_c="$1"; _dst_d="$2"
    [ -d "$_src_c" ] && [ -d "$_dst_d" ] || return 0
    for _cfp in "$_src_c"/*.json; do
        [ -f "$_cfp" ] || continue
        _cfbn="${_cfp##*/}"
        rb_is_cfg_whitelisted "$_cfbn" || continue
        if cp -af "$_cfp" "$_dst_d/${_cfbn}.rb" 2>/dev/null; then
            [ "$_cfbn" = "self_firewall.json" ] && chmod 600 "$_dst_d/${_cfbn}.rb" 2>/dev/null || true
            mv -f "$_dst_d/${_cfbn}.rb" "$_dst_d/$_cfbn" 2>/dev/null || cp -af "$_cfp" "$_dst_d/$_cfbn" 2>/dev/null || true
            rm -f "$_dst_d/${_cfbn}.rb" 2>/dev/null || true
        else
            cp -af "$_cfp" "$_dst_d/$_cfbn" 2>/dev/null || true
        fi
        [ "$_cfbn" = "self_firewall.json" ] && chmod 600 "$_dst_d/$_cfbn" 2>/dev/null || true
    done
    return 0
}

RB_SELF_DIR=${0%/*}

rb_load_proc() {
    _rlp_hnc="$1"
    for _rlp_f in "$_rlp_hnc/bin/hnc_proc.sh" "$RB_SELF_DIR/hnc_proc.sh"; do
        if [ -f "$_rlp_f" ]; then
            . "$_rlp_f"
            return 0
        fi
    done
    return 1
}

rb_uptime_sec() {
    if [ -n "${HNC_RB_UPTIME_OVERRIDE:-}" ]; then
        _rbu="${HNC_RB_UPTIME_OVERRIDE%%.*}"
    else
        _rbuf="${HNC_RB_UPTIME_FILE:-/proc/uptime}"
        [ -r "$_rbuf" ] || return 1
        read -r _rbu _rb_rest < "$_rbuf" 2>/dev/null || return 1
        _rbu="${_rbu%%.*}"
    fi
    case "$_rbu" in ''|*[!0-9]*) return 1 ;; esac
    printf '%s' "$_rbu"
    return 0
}

rb_boot_id() {
    if [ -n "${HNC_RB_BOOT_ID_OVERRIDE:-}" ]; then
        _rbb=$(printf '%s' "$HNC_RB_BOOT_ID_OVERRIDE" | tr -d ' \t\r\n')
    else
        _rbbf="${HNC_RB_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}"
        [ -r "$_rbbf" ] || return 1
        _rbb=$(tr -d ' \t\r\n' < "$_rbbf" 2>/dev/null)
    fi
    [ -n "$_rbb" ] || return 1
    printf '%s' "$_rbb"
    return 0
}

rb_write_observing() {
    _wo_d="$1"
    _wo_ep="${HNC_RB_NOW_OVERRIDE:-$(date +%s 2>/dev/null || echo 0)}"
    case "$_wo_ep" in ''|*[!0-9]*) _wo_ep=0 ;; esac
    _wo_up=$(rb_uptime_sec 2>/dev/null || true)
    _wo_bid=$(rb_boot_id 2>/dev/null || true)
    if [ -n "$_wo_up" ] && [ -n "$_wo_bid" ]; then
        printf '%s %s %s\n' "$_wo_ep" "$_wo_up" "$_wo_bid" > "$_wo_d/rollback.observing.tmp" 2>/dev/null \
            && mv -f "$_wo_d/rollback.observing.tmp" "$_wo_d/rollback.observing" 2>/dev/null \
            || printf '%s %s %s\n' "$_wo_ep" "$_wo_up" "$_wo_bid" > "$_wo_d/rollback.observing" 2>/dev/null || true
    else
        printf '%s\n' "$_wo_ep" > "$_wo_d/rollback.observing" 2>/dev/null || true
    fi
}

# ── 快照 ─────────────────────────────────────────────────────────────
# 返回: 0 = 正常(继续 sync); 3 = pinned 且模块版本没变(跳过 sync);
#       1 = 内部错误(照常继续 sync, 失败不影响开机)。
rb_snapshot() {
    _moddir="$1"; _hnc="$2"; _d=$(rb_data "$_hnc")
    _mod_bn=$(basename "$_moddir" 2>/dev/null)
    if [ -e "$_moddir/update" ] && [ -n "$_mod_bn" ] && [ -d "${HNC_MODULES_UPDATE_ROOT:-/data/adb/modules_update}/$_mod_bn" ]; then
        rb_log "snapshot: live update staged at ${HNC_MODULES_UPDATE_ROOT:-/data/adb/modules_update}/$_mod_bn, skip premature runtime_version rewrite until reboot"
        if [ -s "$_d/rollback.pinned" ]; then
            return 3
        fi
        return 0
    fi
    _new=$(rb_mod_vc "$_moddir")
    [ -n "$_new" ] || _new=unknown
    _old=$(cat "$_d/runtime_version" 2>/dev/null | tr -d ' \r\n')
    _pin=$(cat "$_d/rollback.pinned" 2>/dev/null | tr -d ' \r\n')

    # 钉住: 坏版本还没换新包 → 跳过同步(否则下次开机又拷回来)
    if [ -n "$_pin" ] && [ "$_pin" = "$_new" ]; then
        rb_log "snapshot: pinned at $_new (module unchanged), skip sync"
        return 3
    fi
    if [ -n "$_pin" ] && [ "$_pin" != "$_new" ]; then
        rb_log "snapshot: new version $_new != pinned $_pin, unpin"
        rm -f "$_d/rollback.pinned" "$_d/rollback.json" "$_d/rollback.ack" 2>/dev/null || true
    fi

    if [ "$_new" = "$_old" ] || [ -z "$_old" ]; then
        : # 同版本重启 / 首次安装: 不做快照, 也没有观察期
    else
        _prev="$_hnc/.prev"; _tmp="$_hnc/.prev.tmp"; _bak="$_hnc/.prev.old"
        mkdir -p "$_d" 2>/dev/null || true
        if [ ! -d "$_prev/bin" ] && [ -d "$_bak/bin" ] && [ -f "$_bak/version" ]; then
            rm -rf "$_prev" 2>/dev/null || true
            mv -f "$_bak" "$_prev" 2>/dev/null || true
        fi
        rm -rf "$_tmp" 2>/dev/null || true
        _prev_ver=""
        [ -f "$_prev/version" ] && _prev_ver=$(tr -d ' \t\r\n' < "$_prev/version" 2>/dev/null || true)
        rb_norm_vc "$_old" && _old_norm=$_rb_vc || _old_norm=""
        rb_norm_vc "$_new" && _new_norm=$_rb_vc || _new_norm=""
        rb_norm_vc "$_prev_ver" && _prev_norm=$_rb_vc || _prev_norm=""
        if [ -d "$_prev/bin" ] && [ -n "$(ls -A "$_prev/bin" 2>/dev/null)" ] \
           && rb_is_stable_vc "$_prev_ver" \
           && { [ -f "$_d/rollback.observing" ] || rb_is_prerelease_vc "$_old" || { [ -n "$_prev_norm" ] && [ "$_old_norm" = "$_prev_norm" ]; }; }; then
            rb_log "snapshot: preserve golden stable .prev (vc=$_prev_norm) across v$_old -> v$_new"
            rm -f "$_d/rollback.pinned" "$_d/rollback.json" "$_d/rollback.ack" 2>/dev/null || true
            echo 0 > "$_d/rollback.failstreak" 2>/dev/null || true
            echo 0 > "$_d/rollback.restarts" 2>/dev/null || true
            : > "$_d/rollback.lastpid_httpd" 2>/dev/null || true
            : > "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
            if [ "$_new_norm" != "$_prev_norm" ]; then
                rb_write_observing "$_d"
            else
                rm -f "$_d/rollback.observing" 2>/dev/null || true
            fi
        else
            # 升级: 打包旧运行目录到 .prev(整体换, 失败不影响开机)
            rm -rf "$_tmp" "$_bak" 2>/dev/null || true
            if mkdir -p "$_tmp/bin" "$_tmp/daemon" "$_tmp/webroot" 2>/dev/null \
               && cp -a "$_hnc/bin/." "$_tmp/bin/" 2>/dev/null \
               && cp -a "$_hnc/daemon/." "$_tmp/daemon/" 2>/dev/null \
               && cp -a "$_hnc/webroot/." "$_tmp/webroot/" 2>/dev/null; then
                [ -f "$_hnc/module.prop" ] && cp -af "$_hnc/module.prop" "$_tmp/module.prop" 2>/dev/null || true
                rb_pack_cfg_snapshot "$_d" "$_tmp/data_cfg"
                echo "$_old" > "$_tmp/version" 2>/dev/null || true
                [ -d "$_prev" ] && mv -f "$_prev" "$_bak" 2>/dev/null || true
                if mv -f "$_tmp" "$_prev" 2>/dev/null; then
                    rm -rf "$_bak" 2>/dev/null || true
                    rb_log "snapshot: v$_old -> v$_new packed to .prev"
                else
                    [ -d "$_bak" ] && mv -f "$_bak" "$_prev" 2>/dev/null || true
                    rb_log "snapshot WARN: swap failed, keep old .prev"
                fi
                rm -f "$_d/rollback.pinned" "$_d/rollback.json" "$_d/rollback.ack" 2>/dev/null || true
                # 观察期标记(10 分钟, 哨兵按 30 秒一轮调 observe)
                rb_write_observing "$_d"
                echo 0 > "$_d/rollback.failstreak" 2>/dev/null || true
                echo 0 > "$_d/rollback.restarts" 2>/dev/null || true
                : > "$_d/rollback.lastpid_httpd" 2>/dev/null || true
                : > "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
            else
                rb_log "snapshot WARN: pack failed, boot continues without .prev"
                rm -rf "$_tmp" 2>/dev/null || true
                rm -f "$_d/rollback.json" "$_d/rollback.ack" 2>/dev/null || true
            fi
        fi
    fi
    echo "$_new" > "$_d/runtime_version.tmp" 2>/dev/null \
        && mv -f "$_d/runtime_version.tmp" "$_d/runtime_version" 2>/dev/null \
        || echo "$_new" > "$_d/runtime_version" 2>/dev/null || true
    return 0
}

# ── 观察期一轮 ───────────────────────────────────────────────────────
# 返回: 0 = 继续观察 / 无事; 9 = 已回滚(哨兵本轮后重启核心)。
rb_observe() {
    _hnc="$1"; _d=$(rb_data "$_hnc"); _r=$(rb_run "$_hnc")
    _obs="$_d/rollback.observing"
    [ -f "$_obs" ] || return 0
    _obs_raw=$(sed -n '1p' "$_obs" 2>/dev/null | tr -d '\r')
    _start=""; _start_up=""; _start_bid=""
    {
        read -r _start _start_up _start_bid _obs_rest
    } <<EOF
$_obs_raw
EOF
    case "$_start" in ''|*[!0-9]*) return 0 ;; esac
    case "$_start_up" in ''|*[!0-9]*) _start_up="" ;; esac
    _cur_up=$(rb_uptime_sec 2>/dev/null || true)
    _cur_bid=$(rb_boot_id 2>/dev/null || true)
    if [ -n "$_start_up" ] && [ -n "$_cur_up" ] && [ -n "$_start_bid" ] && [ -n "$_cur_bid" ] \
       && [ "$_start_bid" = "$_cur_bid" ] && [ "$_cur_up" -ge "$_start_up" ]; then
        if [ $(( _cur_up - _start_up )) -ge 600 ]; then
            rb_log "observe: window over (10 min, monotonic), clean"
            rb_observe_cleanup "$_d"
            return 0
        fi
    else
        _now="${HNC_RB_NOW_OVERRIDE:-$(date +%s 2>/dev/null || echo 0)}"
        case "$_now" in ''|*[!0-9]*) _now=0 ;; esac
        if [ $(( _now - _start )) -ge 600 ]; then
            rb_log "observe: window over (10 min), clean"
            rb_observe_cleanup "$_d"
            return 0
        fi
    fi

    rb_load_proc "$_hnc"
    # 测试注入: HNC_RB_STUB 指向桩脚本时可覆盖 pidfile_pid_matches /
    # rb_port_listening(沙箱里没法造 /proc 状态; 生产无此变量, 不生效)。
    if [ -n "$HNC_RB_STUB" ] && [ -f "$HNC_RB_STUB" ]; then
        . "$HNC_RB_STUB"
    fi

    # 核心进程判活: pidfile + /proc/<pid>/cmdline(不依赖 ps 输出格式)
    _httpd_ok=0
    if pidfile_pid_matches "$_r/httpd.pid" hnc_httpd 2>/dev/null; then _httpd_ok=1; fi
    _wd_ok=0
    if pidfile_pid_matches "$_r/watchdog.pid" hnc_watchdog 2>/dev/null; then _wd_ok=1; fi
    _port_ok=0
    if rb_port_listening; then _port_ok=1; fi

    _httpd_pid=$(cat "$_r/httpd.pid" 2>/dev/null | tr -d ' \r\n')
    _wd_pid=$(cat "$_r/watchdog.pid" 2>/dev/null | tr -d ' \r\n')

    # 崩溃重启计数: pid 变了且现在活着 = 重启过一次。第一次看到 pid 只记
    # 基线不计数(快照时 lastpid 清空; 不这样的话健康开机第一轮就 +2, 之后
    # 再有 3 次正常重启 —— 如热点 IP 变化导致 httpd 重绑 —— 就误回滚)。
    # pidfile 暂时没有(进程刚被杀、还没重拉)时保留上一个 pid 作基线。
    _rst=$(rb_readnum "$_d/rollback.restarts")
    _lh=$(cat "$_d/rollback.lastpid_httpd" 2>/dev/null | tr -d ' \r\n')
    _lw=$(cat "$_d/rollback.lastpid_watchdog" 2>/dev/null | tr -d ' \r\n')
    if [ -n "$_httpd_pid" ]; then
        if [ -n "$_lh" ] && [ "$_httpd_pid" != "$_lh" ] && [ "$_httpd_ok" = 1 ]; then _rst=$((_rst + 1)); fi
        printf '%s' "$_httpd_pid" > "$_d/rollback.lastpid_httpd" 2>/dev/null || true
    fi
    if [ -n "$_wd_pid" ]; then
        if [ -n "$_lw" ] && [ "$_wd_pid" != "$_lw" ] && [ "$_wd_ok" = 1 ]; then _rst=$((_rst + 1)); fi
        printf '%s' "$_wd_pid" > "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
    fi
    echo "$_rst" > "$_d/rollback.restarts" 2>/dev/null || true

    _fail=0
    [ "$_httpd_ok" = 1 ] && [ "$_port_ok" = 1 ] && [ "$_wd_ok" = 1 ] || _fail=1
    if [ "$_fail" = 1 ]; then
        _streak=$(($(rb_readnum "$_d/rollback.failstreak") + 1))
    else
        _streak=0
    fi
    echo "$_streak" > "$_d/rollback.failstreak" 2>/dev/null || true

    if [ "$_streak" -ge 6 ] || [ "$_rst" -ge 5 ]; then
        _reason="failstreak=$_streak restarts=$_rst"
        rb_do_rollback "$_hnc" "$_reason"
        return 9
    fi
    return 0
}

rb_readnum() { _v=$(cat "$1" 2>/dev/null | tr -d ' \r\n'); case "$_v" in ''|*[!0-9]*) echo 0 ;; *) echo "$_v" ;; esac; }

# 8444(0x20FC)是否 LISTEN(0A): 读 /proc/net/tcp 与 tcp6, 不依赖 curl/nc。
rb_port_listening() {
    _f1="/proc/net/tcp"; _f2="/proc/net/tcp6"
    for _f in "$_f1" "$_f2"; do
        [ -r "$_f" ] || continue
        if awk 'NR>1 { split($2, a, ":"); if (a[2] == "20FC" && $4 == "0A") { found=1 } }
               END { exit found ? 0 : 1 }' "$_f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

rb_verify_daemon_pid() {
    _vdp_pid="$1"
    _vdp_kw="$2"
    _vdp_proot="${HNC_PROC_ROOT:-/proc}"
    case "$_vdp_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_vdp_pid" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_vdp_pid" = "$PPID" ] && return 1
    if command -v pid_matches >/dev/null 2>&1 && pid_matches "$_vdp_pid" "$_vdp_kw"; then
        return 0
    fi
    if [ ! -s "$_vdp_proot/$_vdp_pid/cmdline" ] && [ -r "$_vdp_proot/$_vdp_pid/comm" ]; then
        _vdp_comm=$(tr -d '\r\n' < "$_vdp_proot/$_vdp_pid/comm" 2>/dev/null)
        case "$_vdp_comm" in
            sh|bash|mksh|ash|dash|zsh|toybox|busybox|toolbox) return 1 ;;
        esac
        [ -n "$_vdp_comm" ] && [ "$_vdp_comm" = "$_vdp_kw" ] && return 0
    fi
    return 1
}

# ── 回滚动作 ─────────────────────────────────────────────────────────
rb_do_rollback() {
    _hnc="$1"; _reason="$2"; _d=$(rb_data "$_hnc"); _r=$(rb_run "$_hnc"); _prev="$_hnc/.prev"
    _bad=$(cat "$_d/runtime_version" 2>/dev/null | tr -d ' \r\n')   # 坏的新版(升级时已写入 runtime_version)
    [ -n "$_bad" ] || _bad=unknown
    _good=$(cat "$_prev/version" 2>/dev/null | tr -d ' \r\n')     # .prev 里的上一版
    [ -n "$_good" ] || _good=unknown
    _at=$(date +%s)

    if [ -f "$_d/rollback.disabled" ]; then
        rb_log "rollback: DISABLED — record only (reason=$_reason)"
        rb_write_record "$_d" "$_bad" "$_good" "$_reason" "$_at" "recorded_only"
        rb_observe_cleanup "$_d"
        return 0
    fi

    if [ -d "$_prev/bin" ]; then
        for _sub in bin daemon webroot; do
            [ -d "$_prev/$_sub" ] || continue
            rm -rf "$_hnc/${_sub}.rb" "$_hnc/${_sub}.bad" 2>/dev/null || true
            if cp -a "$_prev/$_sub" "$_hnc/${_sub}.rb" 2>/dev/null; then
                [ -d "$_hnc/$_sub" ] && mv -f "$_hnc/$_sub" "$_hnc/${_sub}.bad" 2>/dev/null || true
                if mv -f "$_hnc/${_sub}.rb" "$_hnc/$_sub" 2>/dev/null; then
                    rm -rf "$_hnc/${_sub}.bad" 2>/dev/null || true
                else
                    [ -d "$_hnc/${_sub}.bad" ] && mv -f "$_hnc/${_sub}.bad" "$_hnc/$_sub" 2>/dev/null || true
                    cp -a "$_prev/$_sub/." "$_hnc/$_sub/" 2>/dev/null || true
                fi
            else
                cp -a "$_prev/$_sub/." "$_hnc/$_sub/" 2>/dev/null || true
            fi
        done
        [ -f "$_prev/module.prop" ] && cp -af "$_prev/module.prop" "$_hnc/module.prop" 2>/dev/null || true
        rb_restore_cfg_snapshot "$_prev/data_cfg" "$_d"
        chmod 755 "$_hnc/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        chcon u:object_r:system_file:s0 "$_hnc/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        # 拷来拷去 SELinux 上下文会变成 system_data_file, ColorOS 上 Go 进程
        # fork+exec 这种文件报 EPERM(见 bin/hnc_runtime_sync.sh)
        for _b in "$_hnc/bin/"*; do
            [ -f "$_b" ] || continue
            chmod 755 "$_b" 2>/dev/null
            chcon u:object_r:system_file:s0 "$_b" 2>/dev/null || true
        done
        rb_log "rollback: restored .prev (v$_good) over v$_bad (reason=$_reason)"
        rb_write_record "$_d" "$_bad" "$_good" "$_reason" "$_at" "rolled_back"
        printf '%s\n' "$_bad" > "$_d/rollback.pinned.tmp" 2>/dev/null \
            && mv -f "$_d/rollback.pinned.tmp" "$_d/rollback.pinned" 2>/dev/null \
            || printf '%s\n' "$_bad" > "$_d/rollback.pinned" 2>/dev/null || true
        echo "$_good" > "$_d/runtime_version.tmp" 2>/dev/null \
            && mv -f "$_d/runtime_version.tmp" "$_d/runtime_version" 2>/dev/null \
            || echo "$_good" > "$_d/runtime_version" 2>/dev/null || true
        # C007: 重启全部核心守护进程 —— 重新加载真实 hnc_proc.sh(覆盖沙箱 stub),
        # 严格核验 /proc/<pid>/cmdline(或 comm)匹配后才发信号停进程, 严禁裸 kill -9 误杀复用进程。
        rb_load_proc "$_hnc"
        _rb_stop_list=""
        for _pair in "watchdog.pid:hnc_watchdog" \
                     "dpid_guard.pid:hnc_launcher" "launcher.pid:hnc_launcher" \
                     "dpid.child.pid:hnc_dpid" "dpid.pid:hnc_dpid" \
                     "httpd.pid:hnc_httpd" "hotspotd.pid:hotspotd"; do
            _pf=${_pair%%:*}
            _kw=${_pair#*:}
            _pid=$(cat "$_r/$_pf" 2>/dev/null | tr -d ' \r\n')
            if [ -n "$_pid" ]; then
                if rb_verify_daemon_pid "$_pid" "$_kw"; then
                    kill "$_pid" 2>/dev/null || true
                    _rb_stop_list="$_rb_stop_list $_pid:$_kw"
                elif [ -d "${HNC_PROC_ROOT:-/proc}/$_pid" ]; then
                    rb_log "rollback: skip reused pid=$_pid in $_pf (expected $_kw)"
                fi
            fi
            rm -f "$_r/$_pf" 2>/dev/null || true
        done
        _rb_still_alive=0
        for _item in $_rb_stop_list; do
            _spid=${_item%%:*}
            kill -0 "$_spid" 2>/dev/null && { _rb_still_alive=1; break; }
        done
        if [ "$_rb_still_alive" -eq 1 ]; then
            usleep 200000 2>/dev/null || sleep 1
            for _item in $_rb_stop_list; do
                _spid=${_item%%:*}
                _skw=${_item#*:}
                if rb_verify_daemon_pid "$_spid" "$_skw" && kill -0 "$_spid" 2>/dev/null; then
                    kill -9 "$_spid" 2>/dev/null || true
                fi
            done
        fi
        rb_observe_cleanup "$_d"
        return 0
    fi
    rb_log "rollback WARN: no .prev to restore (reason=$_reason)"
    rb_write_record "$_d" "$_bad" "$_good" "$_reason" "$_at" "no_snapshot"
    rb_observe_cleanup "$_d"
    return 1
}

# rollback.json: from = 启动失败的新版, to = 退回到的上一版(versionCode);
# action = rolled_back / recorded_only(rollback.disabled)/ no_snapshot。
# 新记录覆盖旧记录时一并删掉 rollback.ack, 否则上一次的「知道了」会把
# 这次的横幅也藏掉。
rb_write_record() {
    _d="$1"; _from="$2"; _to="$3"; _reason="$4"; _at="$5"; _action="$6"
    rm -f "$_d/rollback.ack" 2>/dev/null || true
    printf '{"from":"%s","to":"%s","reason":"%s","at":%s,"action":"%s"}\n' \
        "$_from" "$_to" "$_reason" "$_at" "$_action" \
        > "$_d/rollback.json.tmp" 2>/dev/null \
        && mv -f "$_d/rollback.json.tmp" "$_d/rollback.json" 2>/dev/null \
        || printf '{"from":"%s","to":"%s","reason":"%s","at":%s,"action":"%s"}\n' \
            "$_from" "$_to" "$_reason" "$_at" "$_action" > "$_d/rollback.json" 2>/dev/null || true
}

rb_observe_cleanup() {
    _d="$1"
    rm -f "$_d/rollback.observing" "$_d/rollback.failstreak" "$_d/rollback.restarts" \
          "$_d/rollback.lastpid_httpd" "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
}

case "${1:-}" in
    snapshot) rb_snapshot "$2" "$3"; exit $? ;;
    observe)  rb_observe "$2"; exit $? ;;
    *)
        echo "usage: $0 snapshot <moddir> <hncdir> | observe <hncdir>" >&2
        exit 4 ;;
esac
