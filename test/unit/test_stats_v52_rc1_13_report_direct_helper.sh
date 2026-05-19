#!/system/bin/sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
fail(){ echo "[FAIL] $*"; exit 1; }
for f in \
  "$ROOT/bin/stats_v52_install_selfcheck.sh" \
  "$ROOT/bin/stats_v52_gray_report.sh" \
  "$ROOT/bin/stats_v52_review_bundle.sh"; do
  [ -f "$f" ] || fail "missing $f"
  sh -n "$f" || fail "syntax $f"
  grep -q 'run_helper_direct\|run_helper_json' "$f" || fail "direct helper wrapper missing in $f"
  ! grep -q 'kill -9.*pid\|kill "\$pid"\|timeout helper:' "$f" || fail "fragile timeout wrapper remains in $f"
done

grep -q 'version=v5.2.0-rc1.13' "$ROOT/module.prop" || fail "module version not rc1.13"
grep -q 'versionCode=520023' "$ROOT/module.prop" || fail "module versionCode not 520023"
echo "[OK] stats_v52_rc1_13_report_direct_helper"
