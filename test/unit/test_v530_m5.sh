#!/system/bin/sh
# test/unit/test_v530_m5.sh — dpid 守护只剩一条链(v5.30 迁移 M5, v5.33 删旧路)。
#
# 测的是行为: 从 service.sh 里按标记把真实开机选择段抽出来跑(不改一行), 外部
# 世界(hnc_launcher / fork_probe 二进制、日志、run 目录)用假的。
#   - C launcher 能用 → choice=launcher; 坏了 / 不在 → direct;
#   - 再也不选 shell guard / Go supervisor(二进制摆在那儿也不选), 也不认
#     run/wd_m5.disabled;
#   - 哨兵循环不判 dpid / launcher(救命路径在 Go 看门狗 m5.go);
#   - dpi_rebind 没 C launcher 时直拉 dpid, 不退回 shell guard。
# 「改动前会失败」: v5.32 的 service.sh 有 run/wd_m5.disabled 开关, 建了它就选
# shell guard(下面第 3 条); 哨兵里还留着 M5 关时的 dpid 救命段(第 5 条);
# dpi_rebind 还有 guard 退路(第 6 条)。

M5_TD="${HNC_TEST_DIR}-m5"
rm -rf "$M5_TD"
mkdir -p "$M5_TD/run" "$M5_TD/logs" "$M5_TD/bin"
SVC="$HNC_REPO_ROOT/service.sh"

# 抽代码段(与线上同一份)
sed -n '/^LAUNCHER_CHOICE=""$/,/^unset _dpid_choice$/p' "$SVC" > "$M5_TD/select.sh"
sed -n '/^# ─── rc30.12.16: 进程哨兵循环/,/^) >> "\$HNC_DIR\/logs\/sentinel.log"/p' "$SVC" > "$M5_TD/sentinel.sh"

# 跑开机选择段。$1 = launcher 状态: ok / abort / none。
# 旧 shell guard / Go supervisor 二进制和 wd_m5.disabled 都摆着(旧版本升级上来的样子)。
m5_select() {
    rm -f "$M5_TD/run/"* "$M5_TD/bin/"*
    : > "$M5_TD/run/wd_m5.disabled"
    printf '#!/bin/sh\n' > "$M5_TD/bin/hnc_dpid_guard.sh"
    printf '#!/bin/sh\n' > "$M5_TD/bin/hnc_dpid_supervisor"
    printf '#!/bin/sh\nexit 0\n' > "$M5_TD/bin/fork_probe"
    case "$1" in
        ok)    printf '#!/bin/sh\necho "hnc_launcher 1.0"\n' > "$M5_TD/bin/hnc_launcher" ;;
        abort) printf '#!/bin/sh\necho "FATAL: TLS segment is underaligned"\nexit 134\n' > "$M5_TD/bin/hnc_launcher" ;;
    esac
    chmod +x "$M5_TD/bin/"*
    (
        RUN="$M5_TD/run"
        log() { :; }
        DPID_BIN="$M5_TD/bin/hnc_dpid"
        DPID_LAUNCHER="$DPID_BIN"
        DPID_LAUNCHER_C="$M5_TD/bin/hnc_launcher"
        FORK_PROBE="$M5_TD/bin/fork_probe"
        DPID_GUARD="$M5_TD/bin/hnc_dpid_guard.sh"
        DPID_SUPERVISOR="$M5_TD/bin/hnc_dpid_supervisor"
        . "$M5_TD/select.sh"
        echo "$LAUNCHER_CHOICE|$(cat "$RUN/dpid_launcher.choice" 2>/dev/null)|${DPID_LAUNCHER##*/}"
    )
}

test_start "m5: 代码段都抽到了(防止标记改名后测试空跑)"
if grep -q 'FORK_PROBE' "$M5_TD/select.sh" && grep -q 'find_live_watchdog_pid' "$M5_TD/sentinel.sh"; then
    test_pass
else
    test_fail "select=$(wc -c < "$M5_TD/select.sh") sentinel=$(wc -c < "$M5_TD/sentinel.sh") 段缺失"
fi

test_start "m5: C launcher 能用 → launcher"
assert_eq "c_launcher|launcher|hnc_launcher" "$(m5_select ok)" "launcher ok" && test_pass

test_start "m5: C launcher 不在 → direct(不选 shell guard / Go supervisor, 不认 wd_m5.disabled)"
assert_eq "|direct|hnc_dpid" "$(m5_select none)" "launcher missing" && test_pass

test_start "m5: C launcher 一跑就 abort → direct"
assert_eq "|direct|hnc_dpid" "$(m5_select abort)" "launcher abort" && test_pass

test_start "m5: 哨兵循环不判 dpid / launcher(救命路径在 Go 看门狗)"
if grep -v '^[[:space:]]*#' "$M5_TD/sentinel.sh" | grep -qE 'DPID_LAUNCHER"|DPID_BIN|dpid_launcher\.choice|wd_m5'; then
    test_fail "sentinel still touches dpid: $(grep -v '^[[:space:]]*#' "$M5_TD/sentinel.sh" | grep -nE 'DPID_LAUNCHER"|DPID_BIN|dpid_launcher\.choice|wd_m5' | head -3)"
else
    test_pass
fi

test_start "m5: shell guard / Go supervisor 在开机脚本与 dpi_rebind 里都没有了"
# (post-fs-data 开机清掉旧版本留下的 run/wd_m5.disabled 是允许的: 只删不读)
_left=$(grep -v '^[[:space:]]*#' "$SVC" "$HNC_REPO_ROOT/bin/dpi_rebind.sh" "$HNC_REPO_ROOT/post-fs-data.sh" \
    | grep -v '"\$HNC_DIR/run/wd_m5\.disabled"' \
    | grep -nE 'hnc_dpid_guard|hnc_dpid_supervisor|wd_m5\.disabled|DPID_GUARD"|DPID_SUPERVISOR')
if [ -z "$_left" ] && [ ! -e "$HNC_REPO_ROOT/bin/hnc_dpid_guard.sh" ] \
   && [ ! -e "$HNC_REPO_ROOT/src/dpid/cmd/dpid_supervisor" ]; then
    test_pass
else
    test_fail "leftover: $(printf '%s' "$_left" | head -3)"
fi
unset _left

rm -rf "$M5_TD"
