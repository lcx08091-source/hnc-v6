#!/system/bin/sh
# test/unit/test_v530_m5.sh — v5.30 T2(迁移 M5): service.sh 的开机选择与哨兵分工。
#
# 测的是行为: 从 service.sh 里按标记把真实代码抽出来跑(不改一行), 外部世界
# (launcher / guard / supervisor 二进制、fork_probe、日志、pidfile)用假的。
#   - m5_enabled: 开关文件 run/wd_m5.disabled;
#   - 开机选择(LAUNCHER_CHOICE="" … unset _dpid_choice): C launcher 不能用时,
#     M5 开 → direct(不选 shell guard / Go supervisor), M5 关 → v5.29 的 guard;
#   - 哨兵第 1 段(dpid / launcher 检查 + 救命路径): M5 开 → 什么都不做(看门狗
#     接管), M5 关 → v5.29 行为(launcher 坏了直拉 dpid、choice 改写 direct)。
# 「改动前会失败」: v5.29 的 service.sh 没有 m5_enabled; 选择段在 M5 开时仍选
# guard; 哨兵在 M5 开时仍直拉 dpid(下面第 3、5 条)。

M5_TD="${HNC_TEST_DIR}-m5"
rm -rf "$M5_TD"
mkdir -p "$M5_TD/run" "$M5_TD/logs" "$M5_TD/bin"
SVC="$HNC_REPO_ROOT/service.sh"

# 抽函数 / 代码段(与线上同一份)
awk 'index($0, "m5_enabled() {") == 1 { f = 1 } f { print } f && $0 == "}" { exit }' "$SVC" > "$M5_TD/fn.sh"
sed -n '/^LAUNCHER_CHOICE=""$/,/^unset _dpid_choice$/p' "$SVC" > "$M5_TD/select.sh"
sed -n '/# v5.30 T2(M5): 默认不再判 dpid/,/# 2\. hnc_watchdog 检查/p' "$SVC" > "$M5_TD/sentinel1.sh"

# 跑开机选择段: $1 = on/off; 只有 shell guard 可用(C launcher 不在)。
m5_select() {
    rm -f "$M5_TD/run/"*
    [ "$1" = off ] && : > "$M5_TD/run/wd_m5.disabled"
    printf '#!/bin/sh\n' > "$M5_TD/bin/hnc_dpid_guard.sh"; chmod +x "$M5_TD/bin/hnc_dpid_guard.sh"
    printf '#!/bin/sh\n' > "$M5_TD/bin/hnc_dpid_supervisor"; chmod +x "$M5_TD/bin/hnc_dpid_supervisor"
    (
        RUN="$M5_TD/run"
        log() { :; }
        . "$M5_TD/fn.sh"
        DPID_BIN="$M5_TD/bin/hnc_dpid"
        DPID_LAUNCHER="$DPID_BIN"
        DPID_LAUNCHER_C="$M5_TD/bin/hnc_launcher"   # 不存在
        FORK_PROBE="$M5_TD/bin/fork_probe"
        DPID_GUARD="$M5_TD/bin/hnc_dpid_guard.sh"
        DPID_SUPERVISOR="$M5_TD/bin/hnc_dpid_supervisor"
        . "$M5_TD/select.sh"
        echo "$LAUNCHER_CHOICE|$(cat "$RUN/dpid_launcher.choice" 2>/dev/null)|$DPID_LAUNCHER"
    )
}

# 跑哨兵第 1 段一轮: $1 = on/off; launcher 死、dpid 死、launcher 日志有 abort。
m5_sentinel() {
    rm -f "$M5_TD/run/"* "$M5_TD/spawned"
    [ "$1" = off ] && : > "$M5_TD/run/wd_m5.disabled"
    printf 'launcher\n' > "$M5_TD/run/dpid_launcher.choice"
    printf 'FATAL: TLS segment is underaligned\nAborted\n' > "$M5_TD/logs/dpid_guard.log"
    printf '#!/bin/sh\necho "$0 $*" >> "%s/spawned"\n' "$M5_TD" > "$M5_TD/bin/hnc_dpid"
    chmod +x "$M5_TD/bin/hnc_dpid"
    (
        RUN="$M5_TD/run"; HNC_DIR="$M5_TD"
        log() { :; }
        sleep() { :; }
        launcher_alive_count() { echo 0; }
        dpid_alive() { return 1; }
        . "$M5_TD/fn.sh"
        DPID_BIN="$M5_TD/bin/hnc_dpid"
        DPID_LAUNCHER="$M5_TD/bin/hnc_launcher"
        DPID_CONFIG="$M5_TD/etc/dpi_config.json"
        DPID_PID="$RUN/dpid.pid"; DPID_GUARD_PID="$RUN/dpid_guard.pid"
        . "$M5_TD/sentinel1.sh"
        wait
    )
    sleep 1 2>/dev/null
    echo "$(cat "$M5_TD/run/dpid_launcher.choice" 2>/dev/null)|$([ -f "$M5_TD/spawned" ] && echo spawned || echo none)"
}

test_start "m5: m5_enabled 按开关文件(默认开)"
_r1=$( (RUN="$M5_TD/run"; . "$M5_TD/fn.sh"; rm -f "$RUN/wd_m5.disabled"; m5_enabled && echo on || echo off) )
_r2=$( (RUN="$M5_TD/run"; . "$M5_TD/fn.sh"; : > "$RUN/wd_m5.disabled"; m5_enabled && echo on || echo off) )
assert_eq "on off" "$_r1 $_r2" "m5_enabled" && test_pass

test_start "m5: 代码段都抽到了(防止标记改名后测试空跑)"
if [ -s "$M5_TD/fn.sh" ] && grep -q 'FORK_PROBE' "$M5_TD/select.sh" && grep -q 'LAUNCHER_BROKEN' "$M5_TD/sentinel1.sh"; then
    test_pass
else
    test_fail "fn=$(wc -c < "$M5_TD/fn.sh") select/sentinel 段缺失"
fi

test_start "m5: 开 → C launcher 不能用时选 direct, 不选 shell guard / Go supervisor"
assert_eq "|direct|$M5_TD/bin/hnc_dpid" "$(m5_select on)" "M5 on selection" && test_pass

test_start "m5: 关 → 退回 v5.29 三选一(shell guard)"
assert_eq "shell_guard|guard|$M5_TD/bin/hnc_dpid_guard.sh" "$(m5_select off)" "M5 off selection" && test_pass

test_start "m5: 开 → 哨兵不判 dpid / launcher(救命路径在 Go 看门狗)"
assert_eq "launcher|none" "$(m5_sentinel on)" "M5 on sentinel" && test_pass

test_start "m5: 关 → 哨兵救命路径照旧(直拉 dpid + choice 改写 direct)"
assert_eq "direct|spawned" "$(m5_sentinel off)" "M5 off sentinel" && test_pass

test_start "m5: dpi_rebind 只在 M5 关时才退回 shell guard"
grep -q '\[ -x "\$GUARD" \] && \[ -f "\$RUN/wd_m5.disabled" \]' "$HNC_REPO_ROOT/bin/dpi_rebind.sh" \
    && test_pass || test_fail "dpi_rebind guard fallback not gated by wd_m5.disabled"

rm -rf "$M5_TD"
