#!/system/bin/sh
# hnc_proc.sh — v5.28 A3: 哨兵的进程判活不再依赖 ps 的输出格式
#
# 背景: v5.8.8 后的进程风暴、v5.25 的「看门狗未运行」误报, 根因都是 shell 里
# 用 pidof + ps 文本管道判断进程 —— ColorOS 的 ps 只显示短名字(没有完整
# 路径、PPID 也不是 1), 哨兵误判「watchdog 死了」每 30 秒多拉一个。
# watchdogfix-v6.1 修过匹配方式但仍是看 ps 的输出格式。这一版直接读
# /proc/<pid>/cmdline(内核说的才算), ps/pidof 降级为兜底。
#
# 供 service.sh `. ` 引入; 单测(test/unit/test_sentinel_proc.sh)用
# HNC_PROC_ROOT 指到假 /proc 目录, 并把 ps mock 成「只有短名字」。
#
# 口径与 Go 侧 findLiveByCmdlineSub(src/dpid/cmd/hnc_watchdog/main.go)一致:
# cmdline 的某个参数恰好是关键字、或以 /<关键字> 结尾才算命中。
#
# 无外部依赖: 纯 shell 内建 + tr(读 cmdline)、cat(pidfile)。判活不用 ps / pidof
# (prune_duplicate_hotspotd 列进程用 /proc + pidof, 只用来找「多出来的」)。
#
# v5.33: service.sh 的 _verify_pid(子串匹配, /proc 里没有该 pid 时还算「对上」)与
# service.sh / watchdog.sh 各一份的 prune_duplicate_hotspotd 并到这里, 只留一份。

# HNC_PROC_ROOT 只为测试覆盖(默认 /proc)。sourced 时不要覆盖已有值。
HNC_PROC_ROOT="${HNC_PROC_ROOT:-/proc}"

# proc_cmdline <pid>: 打印 /proc/<pid>/cmdline 的参数(NUL 换成空格)。空/失败 = 死进程。
proc_cmdline() {
    [ -n "$1" ] || return 1
    tr '\000' ' ' < "$HNC_PROC_ROOT/$1/cmdline" 2>/dev/null
}

# pid_matches <pid> <关键字>:
#   - pid 为空 / 非数字 / 自身($$)或父进程($PPID) / /proc 下无 cmdline → 不匹配;
#   - 若存在 /proc/<pid>/comm, 排除 shell 进程且(目标名 <=15 字符时)要求 comm 精确等于关键字;
#   - 仅提取 cmdline 的第 0 个参数 argv[0](首个 NUL 之前), 要求 ${argv0##*/} 精确等于关键字;
#   - 严禁对整条 cmdline 或后续参数做子串通配, 杜绝误匹配 bash -c "... daemon/hnc_httpd ..."!
pid_matches() {
    local _hp_pid _hp_kw _hp_comm _hp_arg0
    _hp_pid="$1"
    _hp_kw="$2"
    case "$_hp_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$_hp_pid" = "$$" ] && return 1
    [ -n "${PPID:-}" ] && [ "$_hp_pid" = "$PPID" ] && return 1
    [ -n "$_hp_kw" ] || return 1
    [ -r "$HNC_PROC_ROOT/$_hp_pid/cmdline" ] || return 1
    if [ -r "$HNC_PROC_ROOT/$_hp_pid/comm" ]; then
        _hp_comm="$(tr -d '\r\n' < "$HNC_PROC_ROOT/$_hp_pid/comm" 2>/dev/null)"
        case "$_hp_comm" in
            sh|bash|mksh|ash|dash|zsh|toybox|busybox|toolbox) return 1 ;;
        esac
        if [ -n "$_hp_comm" ] && [ "${#_hp_kw}" -le 15 ] && [ "$_hp_comm" != "$_hp_kw" ]; then
            return 1
        fi
    fi
    _hp_arg0="$(tr '\000' '\n' < "$HNC_PROC_ROOT/$_hp_pid/cmdline" 2>/dev/null | head -n 1)"
    [ -n "$_hp_arg0" ] || return 1
    [ "${_hp_arg0##*/}" = "$_hp_kw" ]
}

# pidfile_pid_matches <pidfile> <关键字>: pidfile 里的 pid 活着且 cmdline 对得上。
# pidfile 缺失 / 空 / pid 被复用成别的进程 → false。
pidfile_pid_matches() {
    local _hp_pf _hp_pid
    _hp_pf="$1"
    [ -n "$_hp_pf" ] && [ -f "$_hp_pf" ] || return 1
    _hp_pid="$(cat "$_hp_pf" 2>/dev/null | tr -d ' \r\n')"
    pid_matches "$_hp_pid" "$2"
}

# pidfile_live_pid <pidfile> <关键字>: pidfile_pid_matches 为真时打印该 pid(否则无输出、返回 1)。
pidfile_live_pid() {
    pidfile_pid_matches "$1" "$2" || return 1
    cat "$1" 2>/dev/null | tr -d ' \r\n'
}

# hnc_protect_daemon <pid> [oom_score_adj]:
#   1) 写入 /proc/<pid>/oom_score_adj (默认 -800), 保护核心守护进程免遭 lmkd 误杀;
#   2) 从 Magisk / KernelSU / APatch 管理器 App 的 uid 冻结 cgroup 中迁出整个线程组
#      (写 cgroup.procs), 防止用户切走管理器后 CachedAppOptimizer 将后台守护进程一并冻结。
hnc_protect_daemon() {
    local _hpd_pid="$1" _hpd_oom="${2:--800}" _proot="${HNC_PROC_ROOT:-/proc}" _cg _cur_cg
    case "$_hpd_pid" in ''|*[!0-9]*) return 1 ;; esac
    case "$_hpd_oom" in ''|*[!0-9-]*) _hpd_oom="-800" ;; esac
    if [ -w "$_proot/$_hpd_pid/oom_score_adj" ]; then
        printf '%s\n' "$_hpd_oom" > "$_proot/$_hpd_pid/oom_score_adj" 2>/dev/null || true
    fi
    [ "$_proot" = "/proc" ] || return 0
    for _cg in /sys/fs/cgroup/cgroup.procs \
               /dev/cg2_bpf/cgroup.procs \
               /dev/freezer/cgroup.procs \
               /sys/fs/cgroup/freezer/cgroup.procs \
               /dev/freezer/tasks \
               /sys/fs/cgroup/freezer/tasks; do
        [ -w "$_cg" ] && printf '%s\n' "$_hpd_pid" > "$_cg" 2>/dev/null || true
    done
    _cur_cg=$(cat "/proc/$_hpd_pid/cgroup" 2>/dev/null)
    case "$_cur_cg" in
        *uid_*|*frozen*|*cached*|*restricted*)
            for _cg in /dev/cpuset/cgroup.procs /sys/fs/cgroup/cpuset/cgroup.procs \
                       /dev/memcg/cgroup.procs /sys/fs/cgroup/memory/cgroup.procs; do
                [ -w "$_cg" ] && printf '%s\n' "$_hpd_pid" > "$_cg" 2>/dev/null || true
            done
            ;;
    esac
    return 0
}

# prune_duplicate_hotspotd: hotspotd 只留一个(rc17: 手动重启服务 / 看门狗竞态会留下两个)。
# 留 pidfile 指的那个(活着且确是 hotspotd), 否则留第一个并修 pidfile;
# 其余 kill -9。调用方提供 $RUN 与 log()。
prune_duplicate_hotspotd() {
    local keep p seen _d _all="" _proot="${HNC_PROC_ROOT:-/proc}"
    keep=$(pidfile_live_pid "$RUN/hotspotd.pid" hotspotd)
    if [ "$_proot" = "/proc" ] && { [ "${HNC_DIR:-/data/local/hnc}" != "/data/local/hnc" ] || [ -n "${HNC_TEST_MODE:-}" ]; }; then
        return 0
    fi
    for _d in "$_proot"/[0-9]*; do
        [ -r "$_d/cmdline" ] || continue
        p=${_d##*/}
        pid_matches "$p" hotspotd && _all="$_all $p"
    done
    if [ "$_proot" = "/proc" ]; then
        for p in $(pidof hotspotd 2>/dev/null); do
            pid_matches "$p" hotspotd || continue
            case " $_all " in *" $p "*) ;; *) _all="$_all $p" ;; esac
        done
    fi
    if [ -z "$keep" ]; then
        for p in $_all; do
            [ -n "$p" ] && { keep="$p"; break; }
        done
        [ -n "$keep" ] && echo "$keep" > "$RUN/hotspotd.pid" 2>/dev/null || true
    fi
    seen=0
    for p in $_all; do
        [ -z "$p" ] && continue
        [ "$p" = "$$" ] && continue
        [ -n "${PPID:-}" ] && [ "$p" = "$PPID" ] && continue
        if [ "$p" = "$keep" ] && [ "$seen" -eq 0 ]; then
            seen=1
            continue
        fi
        command -v log >/dev/null 2>&1 && log "killing duplicate hotspotd pid=$p keep=$keep"
        kill -9 "$p" 2>/dev/null || true
    done
}
