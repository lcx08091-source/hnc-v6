#!/system/bin/sh
# v5.3.0-rc3 Smart Queue presets/status/diagnostic regression tests

# This file is sourced by test/run_all.sh after test/lib.sh.

test_start "v5.3 rc3/rc10 sqm_manager exposes presets and current status schema"
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
status=$(HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" status test0)
assert_contains "$status" '"schema": 3' "status should use current schema" || { mock_teardown; return; }
assert_contains "$status" '"presets":' "status should include presets array" || { mock_teardown; return; }
assert_contains "$status" '"detected_leaf"' "status should include detected leaf" || { mock_teardown; return; }
assert_contains "$status" '"recommended_leaf": "fq_codel"' "status should report recommended leaf" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc3 set-preset weaknet persists mode/profile/preset"
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
status=$(HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" set-preset weaknet)
assert_contains "$status" '"preset": "weaknet"' "preset should become weaknet" || { mock_teardown; return; }
assert_contains "$status" '"mode": "auto"' "weaknet preset should enable auto SQM mode" || { mock_teardown; return; }
assert_eq "weaknet" "$(cat "$HNC_TEST_DIR/run/sqm_preset")" "sqm_preset should persist" || { mock_teardown; return; }
assert_eq "auto" "$(cat "$HNC_TEST_DIR/run/sqm_mode")" "sqm_mode should persist from preset" || { mock_teardown; return; }
assert_eq "custom" "$(cat "$HNC_TEST_DIR/run/sqm_profile")" "sqm_profile should persist from preset" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc3 WebUI exposes preset fill and gray diag controls"
html=$(cat "$HNC_REPO_ROOT/webroot/index.html")
assert_contains "$html" 'data-sqm-preset="weaknet"' "settings page should include weaknet preset" || return
assert_contains "$html" 'data-action="fill-sqm-preset"' "device card should expose preset fill button" || return
assert_contains "$html" 'data-action="sqm-gray-diag"' "settings page should expose SQM gray diag" || return
test_pass

test_start "v5.3 rc3 actionSQMSet accepts preset parameter"
go_src=$(cat "$HNC_REPO_ROOT/daemon/hnc_httpd/action_sqm_v53.go")
assert_contains "$go_src" 'preset := strings.TrimSpace' "Go action should parse preset" || return
assert_contains "$go_src" 'set-preset' "Go action should call sqm_manager set-preset" || return
assert_contains "$go_src" 'weaknet' "Go action should allow weaknet preset" || return
test_pass
