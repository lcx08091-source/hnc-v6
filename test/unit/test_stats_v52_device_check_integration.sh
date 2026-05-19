#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"

for f in \
  "$ROOT/bin/stats_v52_device_check.sh" \
  "$ROOT/bin/json_diag_bundle.sh" \
  "$ROOT/bin/json_health_panel.sh" \
  "$ROOT/bin/ci_preflight.sh"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

grep -q 'stats_v52_device_check_json' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'stats_v52_device_check.txt' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'has_stats_v52_device_check' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'STATS_V52_DEVICE_CHECK_RAW' "$ROOT/bin/json_health_panel.sh"
grep -q 'v52_device_check_raw' "$ROOT/bin/json_health_panel.sh"
grep -q 'bin/stats_v52_device_check.sh' "$ROOT/bin/ci_preflight.sh"
grep -q 'HNC preflight hotfix22.4' "$ROOT/bin/ci_preflight.sh"

grep -q 'version=v5.1.0-rc1-hotfix22.4' "$ROOT/module.prop"
grep -q 'versionCode=509224' "$ROOT/module.prop"

# Static safety: device_check is read-only with respect to network core.
! grep -v '^#' "$ROOT/bin/stats_v52_device_check.sh" | grep -q 'capability_probe.sh'
! grep -v '^#' "$ROOT/bin/stats_v52_device_check.sh" | grep -Eq '(^|[[:space:]])tc[[:space:]]|iptables|ip6tables'

echo "[OK] stats_v52_device_check integration"
