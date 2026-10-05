#!/system/bin/sh
# hnc_rollback.sh — v5.29 T3: 升级自检 + 自动回滚。
#
# 目标: 刷了坏包(核心进程起不来)时自动退回上一版。只看「核心进程能
# 不能起来」(httpd 活着 + 8444 在听 + watchdog 活着), 不看网络规则
# —— 网络规则会因为各种原因暂时不健康, 拿它做回滚条件会误伤。
#
# 用法(service.sh 调用, 也可手工):
#   hnc_rollback.sh snapshot <moddir> <hncdir>
#       sync_runtime_from_moddir 之前调: 模块 versionCode 与
#       data/runtime_version 不同(= 刚升级)时, 把运行目录 bin/ daemon/
#       webroot/ 打包到 .prev/(先写临时目录再整体换, 失败不影响开机),
#       开始观察期; 记录新版本。返回 3 = 已钉住(pinned), 调用方跳过同步。
#   hnc_rollback.sh observe <hncdir>
#       观察期内每 30 秒调一次(哨兵): 连续 6 次(3 分钟)httpd 和 watchdog
#       都起不来, 或任一崩溃重启 ≥ 5 次 → 恢复 .prev/ + 写 rollback.json
#       + 钉住新版本 + 重启核心进程。data/rollback.disabled 存在时只记录。
#   hnc_rollback.sh status <hncdir>
#       打印 rollback.json(诊断 / httpd 转出用)。
#
# 端口判定不依赖 curl/nc(手机上不保证有): 读 /proc/net/tcp{,6},
# 本地端口 20FC(8444)且状态 0A(LISTEN)。

HNC_RB_LOG="${HNC_RB_LOG:-/dev/null}"
rb_log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [rollback] $*" >> "$HNC_RB_LOG" 2>/dev/null || true; }

rb_mod_vc() { sed -n 's/^versionCode=//p' "$1/module.prop" 2>/dev/null | head -n1 | tr -d ' \r'; }

rb_data() { echo "$1/data"; }
rb_run() { echo "$1/run"; }

# ── 快照 ─────────────────────────────────────────────────────────────
# 返回: 0 = 正常(继续 sync); 3 = pinned 且模块版本没变(跳过 sync);
#       1 = 内部错误(照常继续 sync, 失败不影响开机)。
rb_snapshot() {
    _moddir="$1"; _hnc="$2"; _d=$(rb_data "$_hnc")
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
        rm -f "$_d/rollback.pinned" 2>/dev/null || true
    fi

    if [ "$_new" = "$_old" ] || [ -z "$_old" ]; then
        : # 同版本重启 / 首次安装: 不做快照, 也没有观察期
    else
        # 升级: 打包旧运行目录到 .prev(整体换, 失败不影响开机)
        _prev="$_hnc/.prev"; _tmp="$_hnc/.prev.tmp"; _bak="$_hnc/.prev.old"
        rm -rf "$_tmp" "$_bak" 2>/dev/null || true
        if mkdir -p "$_tmp/bin" "$_tmp/daemon" "$_tmp/webroot" 2>/dev/null \
           && cp -a "$_hnc/bin/." "$_tmp/bin/" 2>/dev/null \
           && cp -a "$_hnc/daemon/." "$_tmp/daemon/" 2>/dev/null \
           && cp -a "$_hnc/webroot/." "$_tmp/webroot/" 2>/dev/null; then
            echo "$_old" > "$_tmp/version" 2>/dev/null || true
            [ -d "$_prev" ] && mv -f "$_prev" "$_bak" 2>/dev/null || true
            if mv -f "$_tmp" "$_prev" 2>/dev/null; then
                rm -rf "$_bak" 2>/dev/null || true
                rb_log "snapshot: v$_old -> v$_new packed to .prev"
            else
                [ -d "$_bak" ] && mv -f "$_bak" "$_prev" 2>/dev/null || true
                rb_log "snapshot WARN: swap failed, keep old .prev"
            fi
            # 观察期标记(10 分钟, 哨兵按 30 秒一轮调 observe)
            date +%s > "$_d/rollback.observing" 2>/dev/null || true
            echo 0 > "$_d/rollback.failstreak" 2>/dev/null || true
            echo 0 > "$_d/rollback.restarts" 2>/dev/null || true
            : > "$_d/rollback.lastpid_httpd" 2>/dev/null || true
            : > "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
        else
            rb_log "snapshot WARN: pack failed, boot continues without .prev"
            rm -rf "$_tmp" 2>/dev/null || true
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
    _start=$(cat "$_obs" 2>/dev/null | tr -d ' \r\n')
    case "$_start" in ''|*[!0-9]*) return 0 ;; esac
    _now=$(date +%s 2>/dev/null || echo 0)
    if [ $(( _now - _start )) -ge 600 ]; then
        rb_log "observe: window over (10 min), clean"
        rm -f "$_obs" "$_d/rollback.failstreak" "$_d/rollback.restarts" \
              "$_d/rollback.lastpid_httpd" "$_d/rollback.lastpid_watchdog" 2>/dev/null || true
        return 0
    fi

    _proc="$_hnc/bin/hnc_proc.sh"
    [ -f "$_proc" ] && . "$_proc"
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

    # 崩溃重启计数: pid 变了且现在活着 = 重启过一次
    _rst=$(rb_readnum "$_d/rollback.restarts")
    if [ -n "$_httpd_pid" ] && [ "$_httpd_pid" != "$(cat "$_d/rollback.lastpid_httpd" 2>/dev/null | tr -d ' \r\n')" ] \
       && [ "$_httpd_ok" = 1 ]; then _rst=$((_rst + 1)); fi
    if [ -n "$_wd_pid" ] && [ "$_wd_pid" != "$(cat "$_d/rollback.lastpid_watchdog" 2>/dev/null | tr -d ' \r\n')" ] \
       && [ "$_wd_ok" = 1 ]; then _rst=$((_rst + 1)); fi
    echo "$_rst" > "$_d/rollback.restarts" 2>/dev/null || true
    printf '%s' "$_httpd_pid" > "$_d/rollback.lastpid_httpd" 2>/dev/null || true
    printf '%s' "$_wd_pid" > "$_d/rollback.lastpid_watchdog" 2>/dev/null || true

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

# ── 回滚动作 ─────────────────────────────────────────────────────────
rb_do_rollback() {
    _hnc="$1"; _reason="$2"; _d=$(rb_data "$_hnc"); _r=$(rb_run "$_hnc"); _prev="$_hnc/.prev"
    _to=$(cat "$_d/runtime_version" 2>/dev/null | tr -d ' \r\n')   # 坏的新版(升级时已写入 runtime_version)
    [ -n "$_to" ] || _to=unknown
    _from=$(cat "$_prev/version" 2>/dev/null | tr -d ' \r\n')
    [ -n "$_from" ] || _from=unknown
    _at=$(date +%s)

    if [ -f "$_d/rollback.disabled" ]; then
        rb_log "rollback: DISABLED — record only (reason=$_reason)"
        rb_write_record "$_d" "$_from" "$_to" "$_reason" "$_at" "recorded_only"
        rb_observe_cleanup "$_d"
        return 0
    fi

    if [ -d "$_prev/bin" ]; then
        cp -a "$_prev/bin/." "$_hnc/bin/" 2>/dev/null || true
        cp -a "$_prev/daemon/." "$_hnc/daemon/" 2>/dev/null || true
        cp -a "$_prev/webroot/." "$_hnc/webroot/" 2>/dev/null || true
        chmod 755 "$_hnc/daemon/hnc_httpd/hnc_httpd" 2>/dev/null || true
        for _b in "$_hnc/bin/"*; do [ -f "$_b" ] && chmod 755 "$_b" 2>/dev/null; done
        rb_log "rollback: restored .prev (v$_from) over v$_to (reason=$_reason)"
        rb_write_record "$_d" "$_from" "$_to" "$_reason" "$_at" "rolled_back"
        printf '%s\n' "$_to" > "$_d/rollback.pinned.tmp" 2>/dev/null \
            && mv -f "$_d/rollback.pinned.tmp" "$_d/rollback.pinned" 2>/dev/null \
            || printf '%s\n' "$_to" > "$_d/rollback.pinned" 2>/dev/null || true
        echo "$_from" > "$_d/runtime_version.tmp" 2>/dev/null \
            && mv -f "$_d/runtime_version.tmp" "$_d/runtime_version" 2>/dev/null \
            || echo "$_from" > "$_d/runtime_version" 2>/dev/null || true
        # 重启核心进程: 杀掉, 让外层(service / 哨兵 / 拉起链)用旧二进制重拉
        for _pf in httpd.pid watchdog.pid; do
            _pid=$(cat "$_r/$_pf" 2>/dev/null | tr -d ' \r\n')
            case "$_pid" in ''|*[!0-9]*) continue ;; esac
            kill -9 "$_pid" 2>/dev/null || true
            rm -f "$_r/$_pf" 2>/dev/null || true
        done
        rb_observe_cleanup "$_d"
        return 0
    fi
    rb_log "rollback WARN: no .prev to restore (reason=$_reason)"
    rb_write_record "$_d" "$_from" "$_to" "$_reason" "$_at" "no_snapshot"
    rb_observe_cleanup "$_d"
    return 1
}

rb_write_record() {
    _d="$1"; _from="$2"; _to="$3"; _reason="$4"; _at="$5"; _action="$6"
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

# ── status ───────────────────────────────────────────────────────────
rb_status() {
    cat "$2/data/rollback.json" 2>/dev/null || true
}

case "${1:-}" in
    snapshot) rb_snapshot "$2" "$3"; exit $? ;;
    observe)  rb_observe "$2"; exit $? ;;
    status)   rb_status "$@"; exit 0 ;;
    *)
        echo "usage: $0 snapshot <moddir> <hncdir> | observe <hncdir> | status <hncdir>" >&2
        exit 4 ;;
esac
