#!/system/bin/sh
# v5.3 Smart Queue foundation regression tests

# This file is sourced by test/run_all.sh after test/lib.sh.

test_start "capability_probe exports fq_codel/cake/SQM keys"
mock_setup
HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/capability_probe.sh" >/dev/null 2>&1
cap="$HNC_TEST_DIR/run/capabilities.json"
assert_file_exists "$cap" "capabilities.json should be generated" || { mock_teardown; return; }
out=$(cat "$cap")
assert_contains "$out" '"tc_fq_codel_supported": true' "fq_codel support key should be present" || { mock_teardown; return; }
assert_contains "$out" '"tc_cake_supported": true' "cake support key should be present" || { mock_teardown; return; }
assert_contains "$out" '"sqm_supported": true' "sqm_supported should be true when fq_codel/cake probe succeeds" || { mock_teardown; return; }
assert_contains "$out" '"sqm_recommended_mode": "cake"' "cake should be recommended when cake probe succeeds" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "sqm_manager defaults off and persists fq_codel mode"
mock_setup
cat > "$HNC_TEST_DIR/run/capabilities.json" <<'JSON'
{
  "tc_fq_codel_supported": true,
  "tc_cake_supported": false,
  "tc_cake_autorate_ingress_supported": false,
  "sqm_supported": true,
  "sqm_recommended_mode": "fq_codel"
}
JSON
printf '%s\n' test0 > "$HNC_TEST_DIR/run/iface.cache"
mode=$(HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" get-mode)
assert_eq "off" "$mode" "SQM should default to off" || { mock_teardown; return; }
status=$(HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" set-mode fq_codel)
assert_contains "$status" '"mode": "fq_codel"' "set-mode should report fq_codel" || { mock_teardown; return; }
assert_contains "$status" '"active": true' "fq_codel mode should be active when supported" || { mock_teardown; return; }
saved=$(cat "$HNC_TEST_DIR/run/sqm_mode" 2>/dev/null)
assert_eq "fq_codel" "$saved" "sqm_mode file should persist" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "sqm_manager rejects invalid mode"
mock_setup
HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" set-mode badmode >/dev/null 2>&1
rc=$?
assert_exit_nonzero "$rc" "invalid mode should fail" || { mock_teardown; return; }
mock_teardown
test_pass
