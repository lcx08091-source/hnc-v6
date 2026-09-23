#!/system/bin/sh
# hotfix21.1 stats_identity_diag.sh regression tests

SCRIPT="$HNC_REPO_ROOT/bin/stats_identity_diag.sh"

# v5.11: test_start 会 rm -rf 测试目录, 夹具必须在 test_start 之后写(此前写在前面, 脚本永远只看到 missing_devices)
seed_identity() {
mkdir -p "$HNC_TEST_DIR/data" "$HNC_TEST_DIR/run"
cat > "$HNC_TEST_DIR/data/devices.json" <<JSON
{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:01","online":true},"aa:bb:cc:dd:ee:02":{"ip":"192.168.43.10","mac":"aa:bb:cc:dd:ee:02","online":false}}
JSON
cat > "$HNC_TEST_DIR/data/stats_raw.jsonl" <<JSON
{"ts":100,"mac":"aa:bb:cc:dd:ee:01","rx":1,"tx":2}
{"ts":101,"mac":"aa:bb:cc:dd:ee:ff","rx":3,"tx":4}
JSON
}

test_start "stats_identity_diag: detects duplicate IP and unknown raw MAC"
seed_identity
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$SCRIPT" json 2>/dev/null)
assert_contains "$out" '"risk":"duplicate_ip"' && \
  assert_contains "$out" '"duplicate_ip_count":1' && \
  assert_contains "$out" '"unknown_macs":1' && test_pass

test_start "stats_identity_diag: text mode includes identity summary"
seed_identity
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$SCRIPT" text 2>/dev/null)
assert_contains "$out" 'risk=duplicate_ip' && \
  assert_contains "$out" 'devices_total=2' && \
  assert_contains "$out" 'recent_raw_unknown_macs=1' && test_pass

test_start "stats_identity_diag: missing devices.json is non-fatal"
rm -f "$HNC_TEST_DIR/data/devices.json"
out=$(HNC_DIR="$HNC_TEST_DIR" sh "$SCRIPT" json 2>/dev/null)
rc=$?
assert_eq "0" "$rc" "script should not fail" && \
  assert_contains "$out" '"risk":"missing_devices"' && test_pass
