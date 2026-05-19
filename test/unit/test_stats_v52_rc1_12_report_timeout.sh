#!/usr/bin/env sh
set -eu
ROOT=$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)
fail(){ echo "FAIL: $*" >&2; exit 1; }
[ -f "$ROOT/bin/stats_v52_web_status.sh" ] || fail "missing stats_v52_web_status.sh"
[ -f "$ROOT/bin/stats_v52_install_selfcheck.sh" ] || fail "missing stats_v52_install_selfcheck.sh"
[ -f "$ROOT/bin/stats_v52_gray_report.sh" ] || fail "missing stats_v52_gray_report.sh"
[ -f "$ROOT/bin/stats_v52_review_bundle.sh" ] || fail "missing stats_v52_review_bundle.sh"
grep -q 'v52_web_status_raw' "$ROOT/webroot/json-health.html" || fail "json-health.html missing v52_web_status_raw"
grep -q 'v5.2-rc1.12' "$ROOT/bin/stats_v52_install_selfcheck.sh" || fail "selfcheck not rc1.12"
grep -q 'version=v5.2.0-rc1.12' "$ROOT/module.prop" || fail "module.prop version not rc1.12"
# rc1.12 fixes the false timeout/missing bug caused by polling kill -0 on unreaped children.
! grep -q 'while kill -0 "\$pid"' "$ROOT/bin/stats_v52_install_selfcheck.sh" || fail "selfcheck still uses kill -0 polling"
! grep -q 'while kill -0 "\$pid"' "$ROOT/bin/stats_v52_gray_report.sh" || fail "gray_report still uses kill -0 polling"
! grep -q 'while kill -0 "\$pid"' "$ROOT/bin/stats_v52_review_bundle.sh" || fail "review_bundle still uses kill -0 polling"
grep -q 'timeout helper:' "$ROOT/bin/stats_v52_gray_report.sh" || fail "gray_report does not distinguish timeout"
grep -q 'timeout helper:' "$ROOT/bin/stats_v52_review_bundle.sh" || fail "review_bundle does not distinguish timeout"
grep -q 'status\\":\\"timeout' "$ROOT/bin/stats_v52_install_selfcheck.sh" || fail "selfcheck JSON timeout fallback missing"
sh -n "$ROOT/bin/stats_v52_web_status.sh"
sh -n "$ROOT/bin/stats_v52_install_selfcheck.sh"
sh -n "$ROOT/bin/stats_v52_gray_report.sh"
sh -n "$ROOT/bin/stats_v52_review_bundle.sh"
echo "[OK] v5.2 rc1.12 report timeout guard"
