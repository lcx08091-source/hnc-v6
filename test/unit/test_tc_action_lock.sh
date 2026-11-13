#!/system/bin/sh
# Exercise the actual lock functions without dispatching any tc/ip commands.

tc_lock_seed() {
    TC_ACTION_LOCK="$HNC_TEST_DIR/run/tc_action.lock"
    TC_ACTION_STALE_SEC=25; TC_ACTION_LEASE_MAX_SEC=90
    awk '/^tc_action_lock\(\)/ {p=1} /^tc_snapshot_async\(\)/ {p=0} p' \
        "$HNC_REPO_ROOT/bin/tc_manager.sh" > "$HNC_TEST_DIR/lock_functions.sh"
    log() { :; }; log_error() { :; }
    . "$HNC_TEST_DIR/lock_functions.sh"
}

test_start "tc_action_lock treats a fresh directory without owner as initializing"
tc_lock_seed
mkdir "$TC_ACTION_LOCK"
tc_action_lock contender >/dev/null 2>&1; rc=$?
assert_exit_nonzero "$rc" && [ ! -f "$TC_ACTION_LOCK/owner" ] && test_pass

test_start "tc_action_lock reclaims an old abandoned directory without owner"
tc_lock_seed
mkdir "$TC_ACTION_LOCK"
touch -t 200001010000 "$TC_ACTION_LOCK"
tc_action_lock contender >/dev/null 2>&1; rc=$?
owner=$(cat "$TC_ACTION_LOCK/owner" 2>/dev/null)
tc_action_unlock
assert_eq 0 "$rc" && assert_contains "$owner" "$$ contender " && test_pass

test_start "tc_action_lock refuses success if publishing owner fails"
tc_lock_seed
( mv() { return 1; }; tc_action_lock contender >/dev/null 2>&1 ); rc=$?
assert_exit_nonzero "$rc" && [ ! -d "$TC_ACTION_LOCK" ] && test_pass

test_start "tc_action_lock excludes a second writer during mkdir-to-owner publication"
tc_lock_seed
cat > "$HNC_TEST_DIR/worker.sh" <<'SH'
#!/bin/sh
TC_ACTION_LOCK="$HNC_DIR/run/tc_action.lock"; TC_ACTION_STALE_SEC=25; TC_ACTION_LEASE_MAX_SEC=90
log() { :; }; log_error() { :; }
. "$HNC_DIR/lock_functions.sh"
mkdir() {
    command mkdir "$@"; rc=$?
    if [ "$rc" = 0 ] && [ "$1" = "$TC_ACTION_LOCK" ]; then
        : > "$HNC_DIR/created"
        n=0
        while [ ! -f "$HNC_DIR/release" ] && [ "$n" -lt 300 ]; do sleep 0.01; n=$((n+1)); done
    fi
    return "$rc"
}
tc_action_lock first >/dev/null 2>&1
echo "$?" > "$HNC_DIR/first.rc"
SH
HNC_DIR="$HNC_TEST_DIR" sh "$HNC_TEST_DIR/worker.sh" &
lock_worker=$!
n=0
while [ ! -f "$HNC_TEST_DIR/created" ] && [ "$n" -lt 200 ]; do sleep 0.01; n=$((n+1)); done
tc_action_lock second >/dev/null 2>&1; second_rc=$?
: > "$HNC_TEST_DIR/release"
wait "$lock_worker"
first_rc=$(cat "$HNC_TEST_DIR/first.rc" 2>/dev/null)
assert_eq 0 "$first_rc" && assert_exit_nonzero "$second_rc" && test_pass
