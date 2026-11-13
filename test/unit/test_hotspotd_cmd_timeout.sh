#!/system/bin/sh
# Host-only C regression: child process closes stdout but stays alive.
if ! command -v test_start >/dev/null 2>&1; then
    HNC_REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
    . "$HNC_REPO_ROOT/test/lib.sh"
    _hnc_timeout_standalone=1
fi
test_start "hotspotd: command deadline includes child lifetime after stdout EOF"
if ! command -v cc >/dev/null 2>&1; then
    test_skip "host C compiler unavailable"
else
    _hnc_hd="$HNC_REPO_ROOT/daemon/hotspotd"
    if ! _hnc_timeout_out=$(cc -std=gnu11 -Wall -Wextra -Werror -D_GNU_SOURCE \
        "$_hnc_hd/test/test_cmd_timeout.c" "$_hnc_hd/hnc_helpers.c" \
        -o "$HNC_TEST_DIR/test_cmd_timeout" 2>&1); then
        test_fail "compile: $_hnc_timeout_out"
    elif _hnc_timeout_out=$("$HNC_TEST_DIR/test_cmd_timeout" 2>&1); then
        test_pass
    else
        test_fail "$_hnc_timeout_out"
    fi
fi
if [ "${_hnc_timeout_standalone:-0}" = 1 ]; then
    print_test_summary
fi
