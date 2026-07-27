#!/system/bin/sh
# test/unit/test_app_limits_visibility.sh — v5.9.3 BUG-011 连带 / BUG-012 步骤1 / BUG-010
#
# 覆盖三条:
#   BUG-011 连带:apply_app_limits.sh 在 ip_app_map.flat 为空时静默 exit 0,
#     对 hnc_watchdog 看起来完全成功,用户只知道"应用级限速没生效"却无从下手。
#     现在必须打固定可 grep 的 HNC_APP_LIMIT_INACTIVE + 落 run/ marker。
#   BUG-012 步骤1:apply_app_limits.sh(每 30s)与 cleanup.sh 两条真改 tc 的
#     路径完全绕过 tc_manager.sh 的分发器 → tc 快照可以停在几天前。现在要补
#     触发,但必须是**条件触发**:规则集没变时不能每 30s 刷一次
#     (否则 logs/tc_state.log 每天多 2880 行)。
#   BUG-010:cleanup.sh 的 run/ 清理是白名单式逐项 rm,不含 portal_*。

AAL="$HNC_REPO_ROOT/bin/apply_app_limits.sh"
CLEANUP="$HNC_REPO_ROOT/bin/cleanup.sh"

# 造一份"配了应用限速 + 客户端在线"的环境
seed_app_env() {
    mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run" "$HNC_TEST_DIR/logs"
    echo "wlan2" > "$HNC_TEST_DIR/run/active_iface"
    printf '%s\n' "aa:bb:cc:dd:ee:01 douyin 5" > "$HNC_TEST_DIR/data/app_limits.flat"
    printf '%s' '{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.50","name":"phone"}}' \
        > "$HNC_TEST_DIR/data/devices.json"
    rm -f "$HNC_TEST_DIR/run/ip_app_map.flat" \
          "$HNC_TEST_DIR/run/app_limits.applied.sig" \
          "$HNC_TEST_DIR/run/app_limits_inactive.marker" \
          "$HNC_TEST_DIR/run/tc_state.json"
}

run_aal() {
    HNC_DIR="$HNC_TEST_DIR" sh "$AAL" >/dev/null 2>&1
}

app_log() {
    cat "$HNC_TEST_DIR/logs/app_limits.log" 2>/dev/null
}

# ═══ BUG-011 连带:空 ip_app_map 必须可见 ═══════════════════════════

test_start "BUG-011: empty ip_app_map logs a greppable HNC_APP_LIMIT_INACTIVE"
mock_setup
seed_app_env
run_aal
assert_contains "$(app_log)" "HNC_APP_LIMIT_INACTIVE" \
    "空 ip_app_map 必须打固定可 grep 的串,而不是静默 exit 0" && \
    assert_file_exists "$HNC_TEST_DIR/run/app_limits_inactive.marker" \
        "必须落 run/ marker 让 diag / 人工 cat 能定位" && \
    test_pass
mock_teardown

test_start "BUG-011: consecutive inactive rounds accumulate a streak counter"
mock_setup
seed_app_env
run_aal
run_aal
run_aal
streak=$(sed -n '2p' "$HNC_TEST_DIR/run/app_limits_inactive.marker" 2>/dev/null)
assert_eq "3" "$streak" "连续 3 轮失效应记成 streak=3(×30s 即失效时长)" && \
    test_pass
mock_teardown

test_start "BUG-011: marker is cleared once dpid produces the map"
mock_setup
seed_app_env
run_aal
assert_file_exists "$HNC_TEST_DIR/run/app_limits_inactive.marker" "先制造失效状态" || true
printf '%s\n' "1.2.3.4 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
assert_file_not_exists "$HNC_TEST_DIR/run/app_limits_inactive.marker" \
    "映射恢复后必须清掉 marker,否则会一直误报" && \
    test_pass
mock_teardown

test_start "BUG-011: no configured limits is NOT reported as inactive"
mock_setup
seed_app_env
: > "$HNC_TEST_DIR/data/app_limits.flat"    # 用户压根没配
run_aal
assert_not_contains "$(app_log)" "HNC_APP_LIMIT_INACTIVE" \
    "没配应用限速不算失效,不能误报" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/app_limits_inactive.marker" "不应落 marker" && \
    test_pass
mock_teardown

# ═══ BUG-012 步骤1:tc 快照条件触发 ════════════════════════════════

test_start "BUG-012: applying app tc rules refreshes the tc_state snapshot"
mock_setup
seed_app_env
printf '%s\n' "1.2.3.4 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
assert_file_exists "$HNC_TEST_DIR/run/tc_state.json" \
    "真下发了 tc class/filter 就必须刷快照(老实现完全绕过分发器)" && \
    assert_file_exists "$HNC_TEST_DIR/run/app_limits.applied.sig" "应记录本轮规则签名" && \
    test_pass
mock_teardown

test_start "BUG-012: unchanged rule set must NOT refresh the snapshot again"
mock_setup
seed_app_env
printf '%s\n' "1.2.3.4 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
rm -f "$HNC_TEST_DIR/run/tc_state.json"
run_aal    # 规则集一模一样 → 删了再原样加回去,tc 树最终状态一致
assert_file_not_exists "$HNC_TEST_DIR/run/tc_state.json" \
    "规则没变不得刷快照(每 30s 无条件刷会让 tc_state.log 每天多 2880 行)" && \
    test_pass
mock_teardown

test_start "BUG-012: IP churn alone must NOT refresh the snapshot"
mock_setup
seed_app_env
printf '%s\n' "1.2.3.4 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
rm -f "$HNC_TEST_DIR/run/tc_state.json"
# dpid 新观测到一个 IP:只改 iptables MARK,tc 的 class/qdisc/filter 一字节不变
printf '%s\n%s\n' "1.2.3.4 douyin" "5.6.7.8 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
assert_file_not_exists "$HNC_TEST_DIR/run/tc_state.json" \
    "IP 数量变化不影响 tc 树,签名不能把它算进去" && \
    test_pass
mock_teardown

test_start "BUG-012: changing the rate DOES refresh the snapshot"
mock_setup
seed_app_env
printf '%s\n' "1.2.3.4 douyin" > "$HNC_TEST_DIR/run/ip_app_map.flat"
run_aal
rm -f "$HNC_TEST_DIR/run/tc_state.json"
printf '%s\n' "aa:bb:cc:dd:ee:01 douyin 20" > "$HNC_TEST_DIR/data/app_limits.flat"
run_aal
assert_file_exists "$HNC_TEST_DIR/run/tc_state.json" \
    "限速值变了 = tc class 的 rate 变了,必须刷快照" && \
    test_pass
mock_teardown

test_start "BUG-012: cleanup.sh refreshes the snapshot after wiping tc"
mock_setup
seed_app_env
printf '%s' '{"ok":true,"htb_ready":true}' > "$HNC_TEST_DIR/run/tc_state.json"
HNC_DIR="$HNC_TEST_DIR" sh "$CLEANUP" rules >/dev/null 2>&1
# cleanup 刚把 root/ingress/ifb0 qdisc 全删了,快照必须被重写,
# 不能继续留着 htb_ready:true 骗 diag.sh / json_health_panel.sh
content=$(cat "$HNC_TEST_DIR/run/tc_state.json" 2>/dev/null)
assert_contains "$content" '"ts"' "cleanup 后 tc_state.json 必须是新写的快照(含 ts)" && \
    test_pass
mock_teardown

# ═══ BUG-010:portal 残留清理 ═════════════════════════════════════

test_start "BUG-010: cleanup.sh removes portal leftovers from run/"
mock_setup
seed_app_env
printf '%s' '{}' > "$HNC_TEST_DIR/run/portal_pending.json"
printf '%s' '{}' > "$HNC_TEST_DIR/run/portal_sessions.json"
HNC_DIR="$HNC_TEST_DIR" sh "$CLEANUP" rules >/dev/null 2>&1
assert_file_not_exists "$HNC_TEST_DIR/run/portal_pending.json" "portal_pending.json 应被清掉" && \
    assert_file_not_exists "$HNC_TEST_DIR/run/portal_sessions.json" "portal_sessions.json 应被清掉" && \
    test_pass
mock_teardown

test_start "BUG-010: guard keeps portal state when portal is actually installed"
mock_setup
seed_app_env
printf '%s' '{}' > "$HNC_TEST_DIR/run/portal_sessions.json"
# portal 真被合入时 bin/portal_manager.sh 必然存在 —— 那时清会话表 = 强制用户重认证
printf '#\n' > "$HNC_TEST_DIR/bin/portal_manager.sh"
HNC_DIR="$HNC_TEST_DIR" sh "$CLEANUP" rules >/dev/null 2>&1
assert_file_exists "$HNC_TEST_DIR/run/portal_sessions.json" \
    "portal 已安装时守卫必须拦住这条 rm" && \
    test_pass
mock_teardown
