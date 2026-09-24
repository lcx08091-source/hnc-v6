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
