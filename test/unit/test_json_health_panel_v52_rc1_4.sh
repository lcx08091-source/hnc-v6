#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"

grep -q 'stats_v52_review_bundle.sh' "$ROOT/bin/json_health_panel.sh"
grep -q 'has_v52_review_bundle_helper' "$ROOT/bin/json_health_panel.sh"
grep -q 'v52_review_bundle_raw' "$ROOT/bin/json_health_panel.sh"
grep -q 'stats_v52_review_bundle.sh' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'stats_v52_review_bundle.json' "$ROOT/bin/json_diag_bundle.sh"
grep -q 'redact_stream' "$ROOT/bin/stats_v52_review_bundle.sh"
grep -q 'Claude / Gemini / GPT' "$ROOT/bin/stats_v52_review_bundle.sh"
grep -q 'bin/stats_v52_review_bundle.sh' "$ROOT/bin/ci_preflight.sh"

echo '[OK] json_health_panel_v52_rc1_4'
