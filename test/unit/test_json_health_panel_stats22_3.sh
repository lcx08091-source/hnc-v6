#!/usr/bin/env sh
set -eu
ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
PANEL="$ROOT/bin/json_health_panel.sh"
BUNDLE="$ROOT/bin/json_diag_bundle.sh"
[ -f "$PANEL" ]
[ -f "$BUNDLE" ]
sh -n "$PANEL"
sh -n "$BUNDLE"
grep -q 'stats_v52_diag_bundle.sh' "$PANEL"
grep -q 'has_v52_diag_bundle_helper' "$PANEL"
grep -q 'v52_diag_bundle_raw' "$PANEL"
grep -q 'stats_v52_diag_bundle_json' "$BUNDLE"
grep -q 'stats_v52_diag_bundle.txt' "$BUNDLE"
grep -q 'has_stats_v52_diag_bundle' "$BUNDLE"
echo "[OK] json_health_panel_stats22_3 static"
