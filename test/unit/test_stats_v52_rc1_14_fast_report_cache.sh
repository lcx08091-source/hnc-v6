#!/system/bin/sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
fail(){ echo "FAIL: $*" >&2; exit 1; }
[ -f "$ROOT/bin/stats_v52_gray_report.sh" ] || fail "missing gray report"
[ -f "$ROOT/bin/stats_v52_review_bundle.sh" ] || fail "missing review bundle"
grep -q 'FAST_CACHE' "$ROOT/bin/stats_v52_gray_report.sh" || fail "gray report missing fast cache"
grep -q 'HNC_V52_REPORT_REFRESH' "$ROOT/bin/stats_v52_gray_report.sh" || fail "gray report missing refresh override"
grep -q 'stats_v52_gray_report.json' "$ROOT/bin/stats_v52_review_bundle.sh" || fail "review bundle does not consume gray cache"
grep -q 'version=v5.2.0-rc1.14' "$ROOT/module.prop" || fail "module version not rc1.14"
grep -q 'versionCode=520024' "$ROOT/module.prop" || fail "module versionCode not 520024"
echo "[OK] stats_v52_rc1_14_fast_report_cache"
