#!/usr/bin/env sh
set -eu
ROOT=$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)
fail(){ echo "FAIL: $*" >&2; exit 1; }
[ -f "$ROOT/bin/stats_v52_web_status.sh" ] || fail "missing stats_v52_web_status.sh"
[ -f "$ROOT/bin/stats_v52_install_selfcheck.sh" ] || fail "missing stats_v52_install_selfcheck.sh"
[ -f "$ROOT/bin/stats_v52_gray_report.sh" ] || fail "missing stats_v52_gray_report.sh"
[ -f "$ROOT/bin/stats_v52_review_bundle.sh" ] || fail "missing stats_v52_review_bundle.sh"
grep -q 'v52_web_status_raw' "$ROOT/webroot/json-health.html" || fail "json-health.html missing v52_web_status_raw"
grep -q 'v5.2-rc1.11' "$ROOT/bin/stats_v52_install_selfcheck.sh" || fail "selfcheck not rc1.11"
grep -q 'run_helper_timeout' "$ROOT/bin/stats_v52_gray_report.sh" || fail "gray report missing helper timeout"
grep -q 'run_helper_timeout_raw' "$ROOT/bin/stats_v52_review_bundle.sh" || fail "review bundle missing helper timeout"
grep -q 'version=v5.2.0-rc1.11' "$ROOT/module.prop" || fail "module.prop version not rc1.11"
sh -n "$ROOT/bin/stats_v52_web_status.sh"
sh -n "$ROOT/bin/stats_v52_install_selfcheck.sh"
sh -n "$ROOT/bin/stats_v52_gray_report.sh"
sh -n "$ROOT/bin/stats_v52_review_bundle.sh"
echo "[OK] v5.2 rc1.11 consistency"
