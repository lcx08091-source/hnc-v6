#!/system/bin/sh
# hnc_proc.sh — v5.28 A3: 哨兵的进程判活不再依赖 ps 的输出格式
#
# 背景: v5.8.8 后的进程风暴、v5.25 的「看门狗未运行」误报, 根因都是 shell 里
# 用 pidof + `ps -ef | awk` 判断进程 —— ColorOS 的 ps 只显示短名字(没有完整
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
# 无外部依赖: 纯 shell 内建 + tr(读 cmdline)、cat(pidfile)。不用 ps / pidof。

# HNC_PROC_ROOT 只为测试覆盖(默认 /proc)。sourced 时不要覆盖已有值。
HNC_PROC_ROOT="${HNC_PROC_ROOT:-/proc}"

# proc_cmdline <pid>: 打印 /proc/<pid>/cmdline 的参数(NUL 换成空格)。空/失败 = 死进程。
proc_cmdline() {
    [ -n "$1" ] || return 1
    tr '\000' ' ' < "$HNC_PROC_ROOT/$1/cmdline" 2>/dev/null
}

# pid_matches <pid> <关键字>:
#   - pid 为空 / 非数字 / /proc 下没有 cmdline(死了或被回收)→ 不匹配;
#   - cmdline 某个参数 == 关键字, 或以 /<关键字> 结尾 → 匹配;
#   - 其余(前缀、子串、别的进程名)→ 不匹配。
pid_matches() {
    local _hp_pid _hp_kw _hp_cl _hp_tok
    _hp_pid="$1"
    _hp_kw="$2"
    case "$_hp_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -n "$_hp_kw" ] || return 1
    _hp_cl="$(proc_cmdline "$_hp_pid")" || return 1
    [ -n "$_hp_cl" ] || return 1
    for _hp_tok in $_hp_cl; do
        [ "$_hp_tok" = "$_hp_kw" ] && return 0
        case "$_hp_tok" in */"$_hp_kw") return 0 ;; esac
    done
    return 1
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
