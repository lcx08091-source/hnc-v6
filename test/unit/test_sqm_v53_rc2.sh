#!/system/bin/sh
# v5.3.0-rc2 Smart Queue control-plane regression tests

# This file is sourced by test/run_all.sh after test/lib.sh.

test_start "v5.3 rc2 exposes SQM API route and action"
assert_contains "$(grep -R --include='*.go' 'api/sqm' "$HNC_REPO_ROOT/daemon/hnc_httpd" 2>/dev/null)" '/api/sqm' "httpd should route /api/sqm" || return
assert_contains "$(grep -R --include='*.go' 'sqm_set' "$HNC_REPO_ROOT/daemon/hnc_httpd" 2>/dev/null)" 'sqm_set' "httpd should expose sqm_set action" || return
test_pass

test_start "v5.3 rc2 WebUI contains SQM controls"
html=$(cat "$HNC_REPO_ROOT/webroot/index.html")
assert_contains "$html" 'Smart Queue 低延迟模式' "settings page should describe Smart Queue" || return
assert_contains "$html" 'data-sqm-mode="auto"' "settings page should include auto mode" || return
assert_contains "$html" 'data-sqm-mode="cake"' "settings page should include cake mode" || return
assert_contains "$html" 'data-sqm-profile="game"' "settings page should include game profile" || return
test_pass

test_start "sqm_manager persists profile in test mode without json_set deadlock"
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
status=$(HNC="$HNC_TEST_DIR" sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" set-profile game)
assert_contains "$status" '"profile": "game"' "set-profile should report game" || { mock_teardown; return; }
saved=$(cat "$HNC_TEST_DIR/run/sqm_profile" 2>/dev/null)
assert_eq "game" "$saved" "sqm_profile file should persist" || { mock_teardown; return; }
mock_teardown
test_pass
