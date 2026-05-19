#!/usr/bin/env sh
# hotfix21.7 stats shadow opt-in control tests
set -eu

ROOT_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP_BASE="$ROOT_DIR/.tmp/test_stats_shadow_control.$$"
rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE/data" "$TMP_BASE/run" "$TMP_BASE/logs" "$TMP_BASE/bin"

cp "$ROOT_DIR/bin/stats_shadow_control.sh" "$TMP_BASE/bin/stats_shadow_control.sh"
chmod 755 "$TMP_BASE/bin/stats_shadow_control.sh"

OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$TMP_BASE/bin/stats_shadow_control.sh" json)"
echo "$OUT" | grep -q '"effective_enabled":false'
echo "$OUT" | grep -q '"reason":"disabled_by_default"'

HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$TMP_BASE/bin/stats_shadow_control.sh" enable >/dev/null
[ -f "$TMP_BASE/run/stats_shadow.enabled" ]
OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$TMP_BASE/bin/stats_shadow_control.sh" json)"
echo "$OUT" | grep -q '"effective_enabled":true'
echo "$OUT" | grep -q '"reason":"flag:stats_shadow.enabled"'

HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$TMP_BASE/bin/stats_shadow_control.sh" disable >/dev/null
[ ! -f "$TMP_BASE/run/stats_shadow.enabled" ]

cat > "$TMP_BASE/data/config.json" <<'JSON'
{"stats_shadow_enabled":true}
JSON
OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 sh "$TMP_BASE/bin/stats_shadow_control.sh" text)"
echo "$OUT" | grep -q 'effective_enabled=true'
echo "$OUT" | grep -q 'reason=config:stats_shadow_enabled'

OUT="$(HNC_DIR="$TMP_BASE" HNC_TEST_MODE=1 HNC_STATS_SHADOW_ENABLE=0 sh "$TMP_BASE/bin/stats_shadow_control.sh" json)"
echo "$OUT" | grep -q '"effective_enabled":false'
echo "$OUT" | grep -q '"reason":"env:HNC_STATS_SHADOW_ENABLE"'

rm -rf "$TMP_BASE"
echo "test_stats_shadow_control.sh: OK"
