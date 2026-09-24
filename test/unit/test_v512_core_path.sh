#!/system/bin/sh
# test/unit/test_v512_core_path.sh — v5.12 限速核心路径回归
# 覆盖: mark_id 分配 / 默认类保护 / v6 filter 同步 / 陈旧规则清理 / 接口缓存 等。
# 全部走 mock(test/lib.sh 的 PATH 拦截),不碰真实 tc/iptables。

ADR="$HNC_REPO_ROOT/bin/apply_device_rule.sh"

adr() {
    HNC_DIR="$HNC_TEST_DIR" HNC="$HNC_TEST_DIR" sh "$ADR" "$@"
}

# ═══ get_or_assign_mid: 只认本设备块内的 mark_id ═══════════════
test_start "alloc_mid: 设备条目无 mark_id 时不得借用下一台设备的 mid"
mock_setup
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:aa:aa:aa:aa:01":{"whitelist":true},"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","mark_id":5}},"blacklist":[],"whitelist":[]}
EOF
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"aa:aa:aa:aa:aa:01":{"ip":"192.168.43.9","status":"allowed"}}
EOF
out=$(adr alloc_mid aa:aa:aa:aa:aa:01 2>/dev/null | tail -1)
assert_ne "5" "$out" "不能复用 bb:02 的 mark_id=5" && \
    assert_contains "$(cat "$HNC_TEST_DIR/data/rules.json")" '"mark_id"' "应写入新 mark_id" && test_pass
mock_teardown

test_start "alloc_mid: 已有 mark_id 的设备复用自己的 mid"
mock_setup
cat > "$HNC_TEST_DIR/data/rules.json" <<'EOF'
{"version":1,"devices":{"aa:aa:aa:aa:aa:01":{"whitelist":true},"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","mark_id":5}},"blacklist":[],"whitelist":[]}
EOF
cat > "$HNC_TEST_DIR/data/devices.json" <<'EOF'
{"bb:bb:bb:bb:bb:02":{"ip":"192.168.43.2","status":"allowed"}}
EOF
out=$(adr alloc_mid bb:bb:bb:bb:bb:02 2>/dev/null | tail -1)
assert_eq "5" "$out" "bb:02 应复用自己的 5" && test_pass
mock_teardown

# ═══ mark_id=1 不得落到 HTB 父类 1:1 ══════════════════════════
TCM="$HNC_REPO_ROOT/bin/tc_manager.sh"
tcm() {
    HNC_DIR="$HNC_TEST_DIR" sh "$TCM" "$@"
}
TC_TREE="qdisc htb 1: root refcnt 2 r2q 10 default 0x9999
class htb 1:1 root rate 1Gbit ceil 1Gbit
class htb 1:9999 parent 1:1 leaf 9999: prio 0 rate 1Gbit"

test_start "set_limit mark_id=1: 设备 class 用 1:100, 不碰父类 1:1"
mock_setup
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 1 10 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "classid 1:100 htb" "mid=1 应映射到 class 1:100" && \
    assert_mock_not_called "classid 1:1 htb" "绝不能改写父类 1:1" && \
    assert_mock_called "handle 0x800001 fw" "fwmark 仍是 0x800001" && \
    assert_mock_called "prio 101 u32" "u32 优先级仍按 mark_id=1 → 101" && test_pass
mock_teardown

test_start "set_limit mark_id=1 清限速: 不得把父类 1:1 复位成 1000mbit"
mock_setup
mock_set_stdout tc "$TC_TREE"
tcm set_limit wlan2 1 0 0 192.168.43.5 >/dev/null 2>&1
assert_mock_not_called "classid 1:1 htb" "清限速不能改父类 1:1" && test_pass
mock_teardown
