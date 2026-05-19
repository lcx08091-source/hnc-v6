#!/usr/bin/env sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
SCRIPT="$ROOT/bin/stats_v52_diag_bundle.sh"
[ -f "$SCRIPT" ]
sh -n "$SCRIPT"
grep -q 'stats_v52_rc_control.sh' "$SCRIPT"
grep -q 'stats_v52_rc_smoke.sh' "$SCRIPT"
grep -q 'stats_migration_readiness.sh' "$SCRIPT"
grep -q 'stats_compare.sh' "$SCRIPT"
grep -q 'stats_health_summary.sh' "$SCRIPT"
grep -q 'stats_v52_diag_bundle.json' "$SCRIPT"
grep -q 'stats_v52_diag_bundle.txt' "$SCRIPT"
echo "[OK] stats_v52_diag_bundle static"
