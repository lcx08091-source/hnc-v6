#!/system/bin/sh
# test_sentinel_proc.sh — v5.28 A3: 哨兵判活不依赖 ps 输出格式(行为测试)
#
# 场景还原当年 ColorOS 事故: ps 只显示短名字(没有完整路径、PPID 不是 1)、
# pidof 找不到 Go 二进制(它认完整路径)→ 旧逻辑误判 watchdog 死了, 每 30 秒
# 多拉一个进程(进程风暴)。新逻辑读 /proc/<pid>/cmdline, 与 pidfile 对上就判活。
#
# 测的是行为, 不是源码 grep:
#   - bin/hnc_proc.sh 的 pid_matches / pidfile_pid_matches 直接跑;
#   - service.sh 的 find_live_watchdog_pid / dpid_alive / launcher_alive_count
#     从 service.sh 里抽出来跑(awk 按函数名提取, 与线上同一份代码)。

HNC_REPO_ROOT="${HNC_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

# 注意: test_start 会 rm -rf $HNC_TEST_DIR(lib.sh 的 setup_test_env), 所以假
# /proc、pidfile、mock bin 都放在旁边的目录, 跨 test_start 存活。
SENT_TD="${HNC_TEST_DIR}-sent"
SENT_PROC="$SENT_TD/proc"
SENT_RUN="$SENT_TD/run"
SENT_MOCK="$SENT_TD/mockbin"
mkdir -p "$SENT_PROC" "$SENT_RUN" "$SENT_MOCK"

# ── mock ps / pidof: ps 只给短名字(内容可配), pidof 一律找不到 ──
cat > "$SENT_MOCK/ps" <<'EOF'
#!/bin/sh
[ -n "$SENT_PS_OUT" ] && printf '%s\n' "$SENT_PS_OUT"
exit 0
EOF
cat > "$SENT_MOCK/pidof" <<'EOF'
#!/bin/sh
# 模拟 toybox pidof 认不出 Go 二进制的场景
exit 1
EOF
chmod +x "$SENT_MOCK/ps" "$SENT_MOCK/pidof"
SENT_OLD_PATH="$PATH"
export PATH="$SENT_MOCK:$PATH"

# ── 引入被测代码 ──
# 1) bin/hnc_proc.sh(HNC_PROC_ROOT 指到假 /proc)
HNC_PROC_ROOT="$SENT_PROC" . "$HNC_REPO_ROOT/bin/hnc_proc.sh"

# 2) service.sh 的哨兵函数(awk 按函数名提取, 不改一行)
SENT_FNS="$SENT_TD/sent_fns.sh"
: > "$SENT_FNS"
for fn in is_pid_alive process_by_name_alive list_watchdog_pids \
          find_live_watchdog_pid dpid_alive launcher_alive_count; do
    awk -v fn="$fn" '
        index($0, fn "() {") == 1 { infn = 1 }
        infn { print }
        infn && $0 == "}" { exit }
    ' "$HNC_REPO_ROOT/service.sh" >> "$SENT_FNS" || true
done
. "$SENT_FNS"

# RUN 指到假 run 目录(被提取的函数用 $RUN/<pidfile>)
RUN="$SENT_RUN"
export RUN

# ── 工具 ──
mk_cmd() { # $1=fake-pid $2..=argv(NUL 分隔写进假 /proc/<pid>/cmdline)
    _pid="$1"; shift
    mkdir -p "$SENT_PROC/$_pid"
    : > "$SENT_PROC/$_pid/cmdline"
    for _a in "$@"; do
        printf '%s\000' "$_a" >> "$SENT_PROC/$_pid/cmdline"
    done
}
rm_proc() { rm -rf "$SENT_PROC/$1"; }

cleanup_sent() {
    [ -n "$SENT_OLD_PATH" ] && export PATH="$SENT_OLD_PATH"
    for _p in $SENT_REAL_PIDS; do kill "$_p" 2>/dev/null; done
    rm -rf "$SENT_TD"
}
trap cleanup_sent EXIT INT TERM

# ─────────────────────────────────────────────────────────────────
test_start "pid_matches: 参数恰好是关键字 / 以 /关键字 结尾(与 Go findLiveByCmdlineSub 同口径)"
mk_cmd 101 "/data/local/hnc/bin/hnc_watchdog"
pid_matches 101 hnc_watchdog && \
    { mk_cmd 102 hnc_launcher -d; pid_matches 102 hnc_launcher; } && \
    ! pid_matches 101 hnc_watchdog_v2 && test_pass || test_fail "cmdline 匹配口径"

test_start "pid_matches: 子串 / 前缀不算命中(短名字误判的老坑)"
mk_cmd 103 "/data/local/hnc/bin/hnc_watchdog_v2"
mk_cmd 104 "/data/local/hnc/bin/not_hnc_watchdog"
if ! pid_matches 103 hnc_watchdog && ! pid_matches 104 hnc_watchdog; then
    test_pass
else
    test_fail "前缀/子串不应命中"
fi

test_start "pid_matches: pid 不存在 / 非数字 → 判死"
rm_proc 105
if ! pid_matches 105 hnc_watchdog && ! pid_matches abc hnc_watchdog && ! pid_matches "" hnc_watchdog; then
    test_pass
else
    test_fail "死 pid 应不命中"
fi

test_start "pidfile + cmdline 对得上 → 判活(即使 ps 只有短名字、pidof 找不到)"
export SENT_PS_OUT="root 101 999 1 12:00 ? 00:00:01 hnc_watchdog"
mk_cmd 101 "/data/local/hnc/bin/hnc_watchdog"
echo 101 > "$RUN/watchdog.pid"
got=$(find_live_watchdog_pid)
assert_eq "101" "$got" "哨兵不应重复拉起(返回 pidfile 的 pid)" && test_pass

test_start "pidfile 指向的 pid 被复用成别的进程 → 判死(会触发重拉)"
export SENT_PS_OUT=""
echo 106 > "$RUN/watchdog.pid"
mk_cmd 106 "/system/bin/toolbox" "sh" "/system/bin/something_else"
if find_live_watchdog_pid >/dev/null 2>&1; then
    test_fail "pid 复用后应判死"
else
    test_pass
fi

test_start "pidfile 缺失 → 走 ps 兜底(短名字也能找到真进程)"
rm -f "$RUN/watchdog.pid"
sleep 30 &
REALPID=$!
SENT_REAL_PIDS="$SENT_REAL_PIDS $REALPID"
export SENT_PS_OUT="root $REALPID 999 1 12:00 ? 00:00:01 hnc_watchdog"
got=$(find_live_watchdog_pid)
assert_eq "$REALPID" "$got" "兜底逻辑应找到 ps 里的短名字进程" && test_pass

test_start "dpid_alive: pidfile 对上 → 活(不看 ps)"
export SENT_PS_OUT=""
mk_cmd 201 "/data/local/hnc/bin/hnc_dpid" -config /data/local/hnc/etc/dpid.conf
echo 201 > "$RUN/dpid.pid"
if dpid_alive; then
    test_pass
else
    test_fail "dpid pidfile 判活失败"
fi

test_start "dpid_alive: pidfile 失效且 ps/pidof 全盲 → 死(会触发重拉)"
export SENT_PS_OUT=""
echo 202 > "$RUN/dpid.pid"
rm_proc 202
if dpid_alive; then
    test_fail "pidfile 失效应判死"
else
    test_pass
fi

test_start "launcher_alive_count: launcher.pid 对上 → ≥1(ps/pidof 全盲)"
export SENT_PS_OUT=""
mk_cmd 301 "/data/local/hnc/bin/hnc_launcher"
echo 301 > "$RUN/launcher.pid"
c=$(launcher_alive_count)
[ "$c" -ge 1 ] && test_pass || test_fail "count=$c, want ≥1"

test_start "launcher_alive_count: 无 pidfile 时 ps 短名字兜底仍有效"
rm -f "$RUN/launcher.pid" "$RUN/dpid_guard.pid"
export SENT_PS_OUT="root $REALPID 999 1 12:00 ? 00:00:01 hnc_dpid_supervisor"
c=$(launcher_alive_count)
[ "$c" -ge 1 ] && test_pass || test_fail "count=$c, want ≥1(ps 兜底)"

test_start "hnc_proc.sh 独立可用: 不依赖 service.sh 的变量"
if (HNC_PROC_ROOT="$SENT_PROC" . "$HNC_REPO_ROOT/bin/hnc_proc.sh" && pid_matches 101 hnc_watchdog); then
    test_pass
else
    test_fail "hnc_proc.sh 应可独立引入"
fi
