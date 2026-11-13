#!/system/bin/sh
# Run the real manual/restore orchestration with network operations recorded,
# while retaining the common executor, set_all, JSON helpers and TC action lock.

policy_apply_seed() {
    export HNC_DIR="$HNC_TEST_DIR" HNC="$HNC_TEST_DIR" HNC_TEST_MODE=1
    export POLICY_CALLS="$HNC_TEST_DIR/run/policy.calls"
    export POLICY_TC_RC=0 POLICY_MARK_RC=0 POLICY_DELAY_RC=0 POLICY_NETEM_RC=0
    : > "$POLICY_CALLS"
    cat > "$HNC_TEST_DIR/data/rules.json" <<'JSON'
{"devices":{"aa:bb:cc:00:00:05":{"mark_id":7,"ip":"192.168.50.99","limit_enabled":true,"down_mbps":3,"up_mbps":2,"delay_ms":120,"jitter_ms":4,"loss_pct":0.5,"sqm_enabled":true}},"blacklist":[]}
JSON
    cat > "$HNC_TEST_DIR/data/devices.json" <<'JSON'
{"aa:bb:cc:00:00:05":{"ip":"192.168.50.5"}}
JSON
    cat > "$HNC_TEST_DIR/bin/device_detect.sh" <<'SH'
echo ap0
SH
    cat > "$HNC_TEST_DIR/bin/iptables_manager.sh" <<'SH'
echo "ipt|$*" >> "$POLICY_CALLS"
[ "$1" = mark ] && exit "${POLICY_MARK_RC:-0}"
exit 0
SH
    printf '#!%s\n' "$(command -v sh)" > "$HNC_TEST_DIR/bin/hnc_ipc"
    cat >> "$HNC_TEST_DIR/bin/hnc_ipc" <<'SH'
echo "ipc|$*" >> "$POLICY_CALLS"
SH
    chmod +x "$HNC_TEST_DIR/bin/hnc_ipc"
    # This auxiliary sync is separate from the per-device apply contract.
    echo 'exit 0' > "$HNC_TEST_DIR/bin/hnc_clsact_sync.sh"

    awk '/^case "\$1" in$/ {exit} {print}' "$HNC_REPO_ROOT/bin/tc_manager.sh" \
        > "$HNC_TEST_DIR/bin/tc_manager.sh"
    cat >> "$HNC_TEST_DIR/bin/tc_manager.sh" <<'SH'
set_limit() { echo "limit|$*" >> "$POLICY_CALLS"; return "${POLICY_TC_RC:-0}"; }
set_delay() { echo "delay|$*" >> "$POLICY_CALLS"; return "${POLICY_DELAY_RC:-0}"; }
set_sqm() { echo "sqm|$*" >> "$POLICY_CALLS"; }
ip() { return 0; }
current_iface_prefix24() { echo '192.168.50.'; }
tc_limit_supported_runtime() { return 0; }
tc_delay_supported_runtime() { return "${POLICY_NETEM_RC:-0}"; }
uplink_supported_runtime() { return 0; }
install_ingress_mirred() { return 0; }
apply_global_shaper_if_enabled() { return 0; }
_hnc_install_clsact_bpf() { return 0; }
tc_snapshot_async() { return 0; }
SH
    awk 'p {print} /^case "\$1" in$/ {p=1;print}' "$HNC_REPO_ROOT/bin/tc_manager.sh" \
        >> "$HNC_TEST_DIR/bin/tc_manager.sh"
}

policy_apply_limit() {
    sh "$HNC_TEST_DIR/bin/apply_device_rule.sh" limit aa:bb:cc:00:00:05 4 2
}

policy_apply_restore() {
    sh "$HNC_TEST_DIR/bin/tc_manager.sh" restore
}

test_start "manual limit and restore share MARK, rates, delay, SQM and offload"
policy_apply_seed
manual_out=$(policy_apply_limit 2>&1); manual_rc=$?
manual_calls=$(cat "$POLICY_CALLS")
: > "$POLICY_CALLS"
restore_out=$(policy_apply_restore 2>&1); restore_rc=$?
restore_calls=$(cat "$POLICY_CALLS")
assert_eq 0 "$manual_rc" && assert_eq 0 "$restore_rc" \
    && assert_eq "$manual_calls" "$restore_calls" \
    && assert_contains "$manual_calls" 'ipt|mark 192.168.50.5 aa:bb:cc:00:00:05 7' \
    && assert_contains "$manual_calls" 'limit|ap0 7 4 2 192.168.50.5' \
    && assert_contains "$manual_calls" 'delay|ap0 7 120 4 0.5 192.168.50.5' \
    && assert_contains "$manual_calls" 'sqm|ap0 7 on 192.168.50.5' \
    && assert_contains "$manual_calls" 'ipc|OFFLOAD_NOTIFY_LIMIT aa:bb:cc:00:00:05 1' \
    && test_pass

test_start "restore refreshes live IP without rewriting saved policy"
policy_apply_seed
before=$(cat "$HNC_TEST_DIR/data/rules.json")
policy_apply_restore >/dev/null 2>&1; rc=$?
assert_eq 0 "$rc" && assert_eq "$before" "$(cat "$HNC_TEST_DIR/data/rules.json")" \
    && assert_contains "$(cat "$POLICY_CALLS")" 'ipt|mark 192.168.50.5' && test_pass

test_start "unavailable netem keeps manual and restore equivalent without erasing delay policy"
policy_apply_seed
export POLICY_NETEM_RC=1
policy_apply_limit >/dev/null 2>&1; manual_rc=$?
manual_calls=$(cat "$POLICY_CALLS")
before=$(cat "$HNC_TEST_DIR/data/rules.json")
: > "$POLICY_CALLS"
policy_apply_restore >/dev/null 2>&1; restore_rc=$?
delay=$(sh "$HNC_TEST_DIR/bin/json_set.sh" device_get aa:bb:cc:00:00:05 delay_ms)
loss=$(sh "$HNC_TEST_DIR/bin/json_set.sh" device_get aa:bb:cc:00:00:05 loss_pct)
assert_eq 0 "$manual_rc" && assert_eq 0 "$restore_rc" \
    && assert_eq "$manual_calls" "$(cat "$POLICY_CALLS")" \
    && assert_contains "$manual_calls" 'delay|ap0 7 0 0 0 192.168.50.5' \
    && assert_eq 120 "$delay" && assert_eq 0.5 "$loss" \
    && assert_eq "$before" "$(cat "$HNC_TEST_DIR/data/rules.json")" && test_pass

test_start "partial uplink saves downlink and reports a warning"
policy_apply_seed
export POLICY_TC_RC=8
out=$(policy_apply_limit 2>&1); rc=$?
up=$(sh "$HNC_TEST_DIR/bin/json_set.sh" device_get aa:bb:cc:00:00:05 up_mbps)
down=$(sh "$HNC_TEST_DIR/bin/json_set.sh" device_get aa:bb:cc:00:00:05 down_mbps)
assert_eq 0 "$rc" && assert_contains "$out" 'partial_tc_fail=uplink' \
    && assert_eq 0 "$up" && assert_eq 4 "$down" \
    && assert_contains "$(cat "$POLICY_CALLS")" 'ipc|OFFLOAD_NOTIFY_LIMIT' && test_pass

test_start "restore accepts partial uplink without saving failed-rate changes"
policy_apply_seed
export POLICY_TC_RC=8
before=$(cat "$HNC_TEST_DIR/data/rules.json")
policy_apply_restore >/dev/null 2>&1; rc=$?
assert_eq 0 "$rc" && assert_eq "$before" "$(cat "$HNC_TEST_DIR/data/rules.json")" \
    && assert_contains "$(cat "$POLICY_CALLS")" 'delay|ap0 7 120 4 0.5' && test_pass

test_start "manual TC failure returns error without persisting rates or notifying offload"
policy_apply_seed
export POLICY_TC_RC=5
out=$(policy_apply_limit 2>&1); rc=$?
calls=$(cat "$POLICY_CALLS")
down=$(sh "$HNC_TEST_DIR/bin/json_set.sh" device_get aa:bb:cc:00:00:05 down_mbps)
assert_exit_nonzero "$rc" && assert_eq 3 "$down" \
    && assert_contains "$calls" 'ipt|unmark 192.168.50.5 aa:bb:cc:00:00:05 7' \
    && assert_not_contains "$calls" 'ipc|' && test_pass

test_start "restore propagates device TC failure without notifying offload"
policy_apply_seed
export POLICY_TC_RC=5
policy_apply_restore >/dev/null 2>&1; rc=$?
assert_exit_nonzero "$rc" && assert_not_contains "$(cat "$POLICY_CALLS")" 'ipc|' && test_pass

test_start "MARK failure stops manual and restore before TC and offload"
policy_apply_seed
export POLICY_MARK_RC=4
policy_apply_limit >/dev/null 2>&1; manual_rc=$?
policy_apply_restore >/dev/null 2>&1; restore_rc=$?
calls=$(cat "$POLICY_CALLS")
assert_exit_nonzero "$manual_rc" && assert_exit_nonzero "$restore_rc" \
    && assert_not_contains "$calls" 'limit|' && assert_not_contains "$calls" 'ipc|' && test_pass

test_start "busy TC lock leaves existing MARK and offload state alone"
policy_apply_seed
mkdir "$HNC_TEST_DIR/run/tc_action.lock"
printf '%s restore %s\n' "$$" "$(date +%s)" > "$HNC_TEST_DIR/run/tc_action.lock/owner"
policy_apply_limit >/dev/null 2>&1; rc=$?
assert_exit_nonzero "$rc" && assert_eq '' "$(cat "$POLICY_CALLS")" && test_pass
