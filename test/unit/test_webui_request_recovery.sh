#!/system/bin/sh
# Run real WebUI transport/bootstrap functions under Node, without a live backend.
if ! command -v test_start >/dev/null 2>&1; then
    HNC_REPO_ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
    . "$HNC_REPO_ROOT/test/lib.sh"
    _hnc_webui_standalone=1
fi
test_start "WebUI: response body deadlines and complete automatic recovery"
if ! command -v node >/dev/null 2>&1; then
    test_skip "node unavailable"
elif _hnc_webui_out=$(node "$HNC_REPO_ROOT/test/webui/request_recovery_test.js" 2>&1); then
    test_pass
else
    test_fail "$_hnc_webui_out"
fi
if [ "${_hnc_webui_standalone:-0}" = 1 ]; then
    print_test_summary
fi
