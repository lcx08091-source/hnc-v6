#!/system/bin/sh
# The manual and restore paths must select the same device and policy fields.

seed_device_policy() {
    HNC_DIR="$HNC_TEST_DIR"
    . "$HNC_TEST_DIR/bin/hnc_device_policy.sh"
    cat > "$HNC_TEST_DIR/data/devices.json" <<'JSON'
{
  "aa:bb:cc:dd:ee:01": {"name":"no address"},
  "aa:bb:cc:dd:ee:02": {"ip":"192.168.43.2"},
  "aa:bb:cc:dd:ee:03": {"ip":"192.168.43.999"}
}
JSON
    cat > "$HNC_TEST_DIR/data/rules.json" <<'JSON'
{
  "devices": {
    "aa:bb:cc:dd:ee:01": {
      "note":"comma, brace } and quote \"; down_mbps is not a policy",
      "nested":{"down_mbps":99,"sqm_enabled":false},
      "mark_id":7,
      "ip":"192.168.43.8",
      "down_mbps":0.75,
      "up_mbps":2,
      "delay_ms":101,
      "jitter_ms":3,
      "loss_pct":0.5,
      "sqm_enabled":true
    },
    "aa:bb:cc:dd:ee:02": {"mark_id":8},
    "aa:bb:cc:dd:ee:03": {"mark_id":100},
    "aa:bb:cc:dd:ee:04": {"mark_id":0},
    "aa:bb:cc:dd:ee:05": {"mark_id":"7"}
  }
}
JSON
}

test_start "device IP lookup never borrows the next device address"
seed_device_policy
out=$(device_current_ip aa:bb:cc:dd:ee:01)
assert_eq "" "$out" && test_pass

test_start "device IP lookup supports multiline JSON and validates IPv4 octets"
seed_device_policy
out=$(device_current_ip aa:bb:cc:dd:ee:02)
bad=$(device_current_ip aa:bb:cc:dd:ee:03)
assert_eq 192.168.43.2 "$out" && assert_eq "" "$bad" && test_pass

test_start "device policy projects only its own top-level fields from multiline JSON"
seed_device_policy
out=$(device_rule_fields aa:bb:cc:dd:ee:01)
assert_eq '7|192.168.43.8|0.75|2|101|3|0.5|true' "$out" && test_pass

test_start "device policy defaults absent numeric fields and SQM without borrowing fields"
seed_device_policy
out=$(device_rule_fields aa:bb:cc:dd:ee:02)
assert_eq '8||0|0|0|0|0|false' "$out" && test_pass

test_start "device mark lookup and policy projection agree on valid mark range"
seed_device_policy
mid=$(device_rule_mid aa:bb:cc:dd:ee:01)
invalid=""
for suffix in 03 04 05 06; do
    if device_rule_mid "aa:bb:cc:dd:ee:$suffix" >/dev/null; then invalid="$invalid mid:$suffix"; fi
    if device_rule_fields "aa:bb:cc:dd:ee:$suffix" >/dev/null; then invalid="$invalid fields:$suffix"; fi
done
assert_eq 7 "$mid" && assert_eq "" "$invalid" && test_pass

test_start "device policy uses one structured device read for all eight fields"
seed_device_policy
mv "$HNC_TEST_DIR/bin/hnc_json" "$HNC_TEST_DIR/bin/hnc_json_real"
cat > "$HNC_TEST_DIR/bin/hnc_json" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$HNC/data/json_reads"
exec sh "$HNC/bin/hnc_json_real" "$@"
SH
out=$(device_rule_fields aa:bb:cc:dd:ee:01)
reads=$(wc -l < "$HNC_TEST_DIR/data/json_reads" | tr -d ' ')
assert_eq '7|192.168.43.8|0.75|2|101|3|0.5|true' "$out" && assert_eq 1 "$reads" && test_pass

test_start "hnc_json whole-device read retains object boundaries and scalar read compatibility"
seed_device_policy
object=$(sh "$HNC_TEST_DIR/bin/hnc_json" get-device "$HNC_TEST_DIR/data/rules.json" aa:bb:cc:dd:ee:01)
scalar=$(sh "$HNC_TEST_DIR/bin/hnc_json" get-device "$HNC_TEST_DIR/data/rules.json" aa:bb:cc:dd:ee:01 down_mbps)
assert_contains "$object" '"mark_id":7' && assert_not_contains "$object" '"mark_id":8' && assert_eq 0.75 "$scalar" && test_pass
