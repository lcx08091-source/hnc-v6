#!/system/bin/sh
# v5.3.0-rc7 Smart Queue incremental apply regression tests

# This file is sourced by test/run_all.sh after test/lib.sh.

write_caps_fqc_only() {
cat > "$HNC_TEST_DIR/run/capabilities.json" <<'JSON'
{
  "tc_fq_codel_supported": true,
  "tc_cake_supported": false,
  "tc_cake_autorate_ingress_supported": false,
  "sqm_supported": true,
  "sqm_recommended_mode": "fq_codel"
}
JSON
}

mock_htb_default_tree() {
    mock_set_stdout tc 'qdisc htb 1: root refcnt 18 r2q 10 default 9999 direct_packets_stat 0 direct_qlen 3000
class htb 1:9999 root prio 0 rate 1000Mbit ceil 1000Mbit burst 1600b cburst 1600b
qdisc netem 1085: parent 1:85 limit 100 delay 100.0ms
qdisc fq_codel 9999: parent 1:9999 limit 10240p flows 1024 quantum 1514'
}

test_start "v5.3 rc7 SQM apply uses incremental default leaf, not tc restore"
mock_setup
write_caps_fqc_only
mock_htb_default_tree
printf '%s\n' fq_codel > "$HNC_TEST_DIR/run/sqm_mode"
status=$(HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" apply test0 2>&1)
rc=$?
assert_exit_zero "$rc" "incremental fq_codel apply should succeed" || { mock_teardown; return; }
assert_contains "$status" '"mode": "fq_codel"' "apply should return sqm status" || { mock_teardown; return; }
assert_mock_called 'tc|qdisc replace dev test0 parent 1:9999 handle 9999: fq_codel' "apply should only replace default fq_codel leaf" || { mock_teardown; return; }
script=$(cat "$HNC_REPO_ROOT/bin/sqm_manager.sh")
assert_not_contains "$script" 'tc_manager.sh" restore' "sqm_manager apply must not call full tc_manager restore" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc7 unsupported CAKE falls back to fq_codel"
mock_setup
write_caps_fqc_only
mock_htb_default_tree
printf '%s\n' cake > "$HNC_TEST_DIR/run/sqm_mode"
HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" apply test0 >/dev/null 2>&1
rc=$?
assert_exit_zero "$rc" "cake mode should fall back to fq_codel when cake unsupported" || { mock_teardown; return; }
assert_mock_not_called 'cake besteffort' "unsupported cake should not be attempted" || { mock_teardown; return; }
assert_mock_called 'tc|qdisc replace dev test0 parent 1:9999 handle 9999: fq_codel' "fallback should replace default fq_codel leaf" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc7 WebUI has SQM busy guard and CAKE capability title"
html=$(cat "$HNC_REPO_ROOT/webroot/index.html")
assert_contains "$html" 'state.sqmBusy' "WebUI should track sqmBusy" || return
assert_contains "$html" 'SQM 正在应用中，请稍候' "WebUI should show busy guard message" || return
assert_contains "$html" '当前内核不支持 CAKE' "WebUI should explain unsupported CAKE" || return
assert_contains "$html" '增量替换默认 leaf qdisc' "WebUI should describe incremental apply" || return
test_pass
