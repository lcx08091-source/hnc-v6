#!/system/bin/sh
# Exercise production watchdog actions against isolated shell command stubs.

seed_watchdog_restore_policy() {
    HNC_DIR="$HNC_TEST_DIR"; export HNC_DIR
    RUN="$HNC_DIR/run"; LOG="$HNC_DIR/logs/watchdog.log"; STATE_FILE="$RUN/hnc_state"
    HNC_RESTORE_RC=0; HNC_INIT_RC=0; HNC_TEST_TC_UNSUPPORTED=0
    export HNC_RESTORE_RC HNC_INIT_RC
    for name in restore_device_rules full_restore do_full_init do_migrate; do
        awk -v name="$name" '$0==name "() {" {p=1} p {print} p && /^}/ {exit}' \
            "$HNC_REPO_ROOT/bin/watchdog.sh" > "$RUN/$name.sh"
        . "$RUN/$name.sh"
    done
    log() { :; }; log_error() { :; }
    get_iface() { echo wlan2; }
    tc_repair_allowed() { return 0; }
    tc_repair_record() { echo "$1" >> "$RUN/repair_results"; }
    run_capability_probe_active() { :; }
    watchdog_tc_core_supported() { return "$HNC_TEST_TC_UNSUPPORTED"; }
    watchdog_mark_tc_unsupported_once() { :; }
    sleep() { :; } # The delayed restore also runs immediately in this isolated test.
    cat > "$HNC_DIR/bin/tc_manager.sh" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$HNC_DIR/run/tc_calls"
case "$1" in
    restore) exit "${HNC_RESTORE_RC:-0}" ;;
    init) exit "${HNC_INIT_RC:-0}" ;;
esac
exit 0
SH
    for name in iptables_manager whitelist_sync quic_block_sync connblock_sync encdns_sync webui_guard v6_sync; do
        printf '#!/bin/sh\nexit 0\n' > "$HNC_DIR/bin/$name.sh"
    done
    echo '{"hotspot_iface":"auto","devices":{}}' > "$HNC_DIR/data/rules.json"
    echo PENDING > "$STATE_FILE"
}

test_start "watchdog restore failure stays pending and propagates the original error"
seed_watchdog_restore_policy
HNC_RESTORE_RC=1
full_restore test_failure; rc=$?
assert_eq 1 "$rc" && assert_file_exists "$RUN/tc_restore_pending" \
    && assert_eq PENDING "$(cat "$STATE_FILE")" && test_pass

test_start "watchdog successful restore clears pending even after an init warning"
seed_watchdog_restore_policy
HNC_INIT_RC=1
echo 1 > "$RUN/tc_restore_pending"
full_restore test_success; rc=$?
assert_eq 0 "$rc" && assert_file_not_exists "$RUN/tc_restore_pending" && test_pass

test_start "watchdog initial restoration failure never commits ACTIVE"
seed_watchdog_restore_policy
HNC_RESTORE_RC=1
do_full_init wlan2 192.168.43.1; rc=$?
assert_eq 1 "$rc" && assert_eq PENDING "$(cat "$STATE_FILE")" \
    && assert_file_exists "$RUN/tc_restore_pending" \
    && assert_eq '"auto"' "$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface)" && test_pass

test_start "watchdog unsupported-TC initialization still requires blacklist restoration success"
seed_watchdog_restore_policy
HNC_RESTORE_RC=1; HNC_TEST_TC_UNSUPPORTED=1
do_full_init wlan2 192.168.43.1; rc=$?
assert_eq 1 "$rc" && assert_eq PENDING "$(cat "$STATE_FILE")" \
    && assert_file_exists "$RUN/tc_restore_pending" && test_pass

test_start "watchdog migration restoration failure returns to PENDING"
seed_watchdog_restore_policy
echo ACTIVE:wlan2 > "$STATE_FILE"
HNC_RESTORE_RC=12
do_migrate wlan2 ap0 192.168.43.1; rc=$?
assert_eq 12 "$rc" && assert_eq PENDING "$(cat "$STATE_FILE")" \
    && assert_file_exists "$RUN/tc_restore_pending" && test_pass

test_start "watchdog initialization and migration keep auto preference separate from runtime interface"
seed_watchdog_restore_policy
do_full_init wlan2 192.168.43.1; init_rc=$?
wait
init_state=$(cat "$STATE_FILE")
do_migrate wlan2 ap0 192.168.43.1; migrate_rc=$?
assert_eq 0 "$init_rc" && assert_eq 0 "$migrate_rc" \
    && assert_eq ACTIVE:wlan2 "$init_state" && assert_eq ACTIVE:ap0 "$(cat "$STATE_FILE")" \
    && assert_eq '"auto"' "$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface)" \
    && assert_file_not_exists "$RUN/tc_restore_pending" && test_pass

test_start "watchdog migration preserves a user's explicit interface preference"
seed_watchdog_restore_policy
echo '{"hotspot_iface":"wlan3","devices":{}}' > "$HNC_DIR/data/rules.json"
do_migrate wlan2 ap0 192.168.43.1; rc=$?
assert_eq 0 "$rc" && assert_eq ACTIVE:ap0 "$(cat "$STATE_FILE")" \
    && assert_eq '"wlan3"' "$(sh "$HNC_DIR/bin/hnc_json" get-top "$HNC_DIR/data/rules.json" hotspot_iface)" && test_pass
