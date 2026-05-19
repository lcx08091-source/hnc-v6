#!/bin/sh
# Static regression for v5.2-rc1.3 health panel gray report wiring.

set -eu
ROOT="$(CDPATH= cd -- "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"

grep -q 'STATS_V52_GRAY_REPORT_RAW' "$ROOT/bin/json_health_panel.sh"
grep -q 'v52_gray_report_raw' "$ROOT/bin/json_health_panel.sh"
grep -q 'stats_v52_gray_report.sh' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'stats_v52_gray_report_json' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'stats_v52_gray_report.sh' "$ROOT/bin/ci_preflight.sh"

echo "[OK] json_health_panel_v52_rc1_3"
