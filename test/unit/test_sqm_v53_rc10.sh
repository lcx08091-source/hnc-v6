#!/system/bin/sh
# v5.3.0-rc10 SQM offline hotspot / stale iface regression tests

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

test_start "v5.3 rc10 SQM apply skips cleanly when cached iface is absent"
mock_setup
write_caps_fqc_only
printf '%s\n' fq_codel > "$HNC_TEST_DIR/run/sqm_mode"
printf '%s\n' wlan2 > "$HNC_TEST_DIR/run/iface.cache"
mock_set_exit ip 1
out=$(HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" apply wlan2 2>&1)
rc=$?
assert_exit_zero "$rc" "apply should save and skip, not fail, when hotspot iface is missing" || { mock_teardown; return; }
assert_contains "$out" 'iface_present": false' "status should report iface_present=false" || { mock_teardown; return; }
assert_contains "$out" 'can_apply": false' "status should report can_apply=false" || { mock_teardown; return; }
assert_contains "$out" '开启热点后再应用' "status should explain saved-for-later behavior" || { mock_teardown; return; }
assert_mock_not_called 'tc|qdisc replace dev wlan2 parent 1:9999' "missing iface must not run tc qdisc replace" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc10 SQM status marks hotspot closed as pending instead of active"
mock_setup
write_caps_fqc_only
printf '%s\n' auto > "$HNC_TEST_DIR/run/sqm_mode"
printf '%s\n' wlan2 > "$HNC_TEST_DIR/run/iface.cache"
mock_set_exit ip 1
out=$(HNC="$HNC_TEST_DIR" HNC_DIR="$HNC_TEST_DIR" HNC_TEST_MODE=1 sh "$HNC_REPO_ROOT/bin/sqm_manager.sh" status 2>/dev/null)
assert_contains "$out" '"schema": 3' "rc10 status should bump schema to 3" || { mock_teardown; return; }
assert_contains "$out" '"active": false' "closed hotspot should not report active SQM" || { mock_teardown; return; }
assert_contains "$out" '"iface_present": false' "closed hotspot should report stale/missing iface" || { mock_teardown; return; }
assert_contains "$out" '"available": true' "manager should remain available even when hotspot is closed" || { mock_teardown; return; }
mock_teardown
test_pass

test_start "v5.3 rc10 WebUI explains saved SQM settings while hotspot is closed"
html=$(cat "$HNC_REPO_ROOT/webroot/index.html")
assert_contains "$html" '热点未开启或热点接口不存在，SQM 设置已保存' "WebUI should explain offline hotspot state" || return
assert_contains "$html" '已保存，开启热点后再应用' "toast should show saved-for-later suffix" || return
assert_contains "$html" 'st.iface_present === false ?' "WebUI should branch on iface_present" || return
test_pass
