#!/system/bin/sh
# test/unit/test_iptables_tc.sh — iptables_manager.sh 和 tc_manager.sh 单元测试
# 这些测试使用 mock 命令(shell function),不调用真实 iptables/tc

IPT_MGR="$HNC_REPO_ROOT/bin/iptables_manager.sh"
TC_MGR="$HNC_REPO_ROOT/bin/tc_manager.sh"

# helper: 在隔离环境跑 iptables_manager
ipt() {
    HNC_DIR="$HNC_TEST_DIR" sh "$IPT_MGR" "$@"
}
tcm() {
    HNC_DIR="$HNC_TEST_DIR" sh "$TC_MGR" "$@"
}

# ═══ iptables_manager.sh: mark_device ════════════════════
test_start "mark_device with valid params calls iptables -A HNC_MARK"
mock_setup
ipt mark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_mock_called "iptables|" && \
    assert_mock_called "HNC_MARK" && test_pass
mock_teardown

test_start "mark_device with empty IP returns error"
mock_setup
ipt mark "" aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
rc=$?
assert_exit_nonzero "$rc" "should fail with empty ip" && test_pass
mock_teardown

test_start "mark_device generates correct mark hex (mark_id=1 → 0x800001)"
mock_setup
ipt mark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_mock_called "0x800001" "should use 0x800001 for mark_id=1" && test_pass
mock_teardown

test_start "mark_device generates correct mark hex (mark_id=59 → 0x80003b)"
mock_setup
ipt mark 192.168.43.5 aa:bb:cc:dd:ee:ff 59 >/dev/null 2>&1
assert_mock_called "0x80003b" "should use 0x80003b for mark_id=59" && test_pass
mock_teardown

test_start "mark_device sets src+mac filter (precise)"
mock_setup
ipt mark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_mock_called "192.168.43.5" && \
    assert_mock_called "aa:bb:cc:dd:ee:ff" && test_pass
mock_teardown

test_start "mark_device sets HNC_STATS for traffic accounting"
mock_setup
ipt mark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_mock_called "HNC_STATS" && test_pass
mock_teardown

# ═══ v3.4.11 P1-4 GC stale IP rules ═════════════════════
test_start "mark_device gc strips old IPs for same MAC"
mock_setup
# 模拟 iptables -S HNC_MARK 输出含旧 IP
mock_set_stdout iptables "-A HNC_MARK -s 192.168.43.5/32 -m mac --mac-source aa:bb:cc:dd:ee:ff -j MARK --set-xmark 0x800001/0xffffffff
-A HNC_MARK -d 192.168.43.5/32 -j MARK --set-xmark 0x800001/0xffffffff"
ipt mark 192.168.43.99 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
# GC 应该尝试删除旧 IP 的规则
assert_mock_called "192.168.43.5" "should reference old IP for cleanup" && test_pass
mock_teardown

# ═══ unmark_device ═══════════════════════════════════════
test_start "unmark_device deletes mark rules"
mock_setup
ipt unmark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_mock_called "HNC_MARK" && test_pass
mock_teardown

# Patch 4.b hotfix: 幂等清理操作即使所有 iptables -D 失败也必须 return 0
# 真机场景:热点关闭 → 链已 cleanup → iptables -D 一条不存在的规则全部失败
# 修复前:函数最后一条 iptables 命令的 exit code 泄露 → unmark 返回 1 → WebUI clearLimit 报"失败"
test_start "unmark_device returns 0 even when all iptables -D fail (idempotent cleanup)"
mock_setup
mock_set_exit iptables 1
mock_set_exit ip6tables 1
ipt unmark 192.168.43.5 aa:bb:cc:dd:ee:ff 1 >/dev/null 2>&1
assert_exit_zero "$?" "unmark_device must return 0 when iptables fails (idempotent)" && test_pass
mock_teardown

test_start "blacklist_remove returns 0 even when all iptables -D fail (idempotent cleanup)"
mock_setup
mock_set_exit iptables 1
mock_set_exit ip6tables 1
ipt blacklist_remove 192.168.43.5 aa:bb:cc:dd:ee:ff >/dev/null 2>&1
assert_exit_zero "$?" "blacklist_remove must return 0 when iptables fails (idempotent)" && test_pass
mock_teardown

test_start "whitelist_remove returns 0 even when all iptables -D fail (idempotent cleanup)"
mock_setup
mock_set_exit iptables 1
mock_set_exit ip6tables 1
ipt whitelist_remove 192.168.43.5 aa:bb:cc:dd:ee:ff >/dev/null 2>&1
assert_exit_zero "$?" "whitelist_remove must return 0 when iptables fails (idempotent)" && test_pass
mock_teardown

# ═══ tc_manager.sh: set_limit ════════════════════════════
test_start "set_limit calls tc class for download direction"
mock_setup
mock_set_stdout tc ""  # 让 class_exists 返回空(不存在)
tcm set_limit wlan2 1 10 0 192.168.43.5 >/dev/null 2>&1
# 应该调 tc class add for iface 1:1
assert_mock_called "tc|" && test_pass
mock_teardown

test_start "set_limit calls tc class for upload direction (ifb0)"
mock_setup
mock_set_stdout tc ""
tcm set_limit wlan2 1 0 10 192.168.43.5 >/dev/null 2>&1
assert_mock_called "ifb0" "upload should use ifb0" && test_pass
mock_teardown

test_start "set_limit with both dl and ul touches both interfaces"
mock_setup
mock_set_stdout tc ""
tcm set_limit wlan2 1 5 10 192.168.43.5 >/dev/null 2>&1
assert_mock_called "wlan2" && \
    assert_mock_called "ifb0" && test_pass
mock_teardown

test_start "set_limit with 0 dl 0 ul does not crash"
mock_setup
mock_set_stdout tc ""
tcm set_limit wlan2 1 0 0 192.168.43.5 >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "should succeed with all-zero" && test_pass
mock_teardown

# ═══ set_delay ═══════════════════════════════════════════
test_start "set_delay with delay only generates netem"
mock_setup
mock_set_stdout tc ""
tcm set_delay wlan2 1 100 0 0 192.168.43.5 >/dev/null 2>&1
assert_mock_called "netem" && test_pass
mock_teardown

# v3.4.11 P0-3 回归: loss-only 必须有效
test_start "set_delay with loss-only (delay=0 jitter=0 loss=5) still generates netem"
mock_setup
mock_set_stdout tc ""
tcm set_delay wlan2 1 0 0 5 192.168.43.5 >/dev/null 2>&1
# v3.4.11 P0-3 回归: 必须调用 tc qdisc 设 netem,且参数包含 loss
assert_mock_called "netem" "loss-only must produce netem qdisc" && \
    assert_mock_called "loss" "must include loss param" && test_pass
mock_teardown

test_start "set_delay with all zero clears delay"
mock_setup
mock_set_stdout tc "class htb 1:1 parent 1:1 leaf 1001: prio 0 rate 1Gbit"
tcm set_delay wlan2 1 0 0 0 192.168.43.5 >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "should succeed" && test_pass
mock_teardown

# ═══ v3.4.12 clsact ingress filter parent ═══════════════
test_start "init_tc detects clsact and uses ffff:fff2 for filter parent"
mock_setup
mock_set_stdout tc "qdisc clsact ffff: parent ffff:fff1"
mock_set_stdout ip "5: wlan2: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc clsact"
tcm init wlan2 >/dev/null 2>&1
# 必须看到 parent ffff:fff2(v3.4.12 修复)
output=$(cat "$MOCK_LOG" 2>/dev/null)
assert_contains "$output" "ffff:fff2" "v3.4.12 fix: must use ffff:fff2 on clsact" && test_pass
mock_teardown

test_start "init_tc on legacy ingress uses bare ffff:"
mock_setup
mock_set_stdout tc ""  # 没有 clsact
tcm init wlan2 >/dev/null 2>&1
# 应该 add ingress qdisc
assert_mock_called "ingress" && test_pass
mock_teardown

# ═══ remove_device ═══════════════════════════════════════
test_start "remove_device deletes class on both interfaces"
mock_setup
tcm remove wlan2 1 >/dev/null 2>&1
assert_mock_called "wlan2" && \
    assert_mock_called "ifb0" && test_pass
mock_teardown

# ═══ HTB rate calculation ═════════════════════════════════
test_start "set_limit with 24 Mbps generates correct rate string"
mock_setup
mock_set_stdout tc ""
tcm set_limit wlan2 59 0 24 192.168.43.5 >/dev/null 2>&1
# HNC 内部用 kbit 表示(24Mbps = 24000kbit)
# 同时验证 ifb0 上的 class 1:59 被建好
assert_mock_called "24000kbit" "rate should be 24000kbit (=24Mbps)" && \
    assert_mock_called "1:59" "should target class 1:59 (mark_id=59)" && test_pass
mock_teardown
