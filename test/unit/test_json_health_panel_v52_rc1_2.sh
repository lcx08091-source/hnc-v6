#!/usr/bin/env sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"

grep -q 'stats_v52_install_selfcheck.sh' "$ROOT/bin/json_health_panel.sh"
grep -q 'has_v52_install_selfcheck_helper' "$ROOT/bin/json_health_panel.sh"
grep -q 'v52_install_selfcheck_raw' "$ROOT/bin/json_health_panel.sh"
grep -q 'stats_v52_install_selfcheck_json' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'stats_v52_install_selfcheck.txt' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'has_stats_v52_install_selfcheck' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'bin/stats_v52_install_selfcheck.sh' "$ROOT/bin/ci_preflight.sh"

echo "[OK] json_health_panel_v52_rc1_2"
