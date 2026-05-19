#!/usr/bin/env sh
set -eu

TMPDIR="${TMPDIR:-/tmp}/hnc_stats_source_diag.$$"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR/bin" "$TMPDIR/data" "$TMPDIR/run"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

ROOT="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$ROOT/bin/stats_source_diag.sh" json > "$TMPDIR/out1.json"
grep -q '"default_source":"legacy"' "$TMPDIR/out1.json"
grep -q '"api_supported_sources":\["legacy","shadow"\]' "$TMPDIR/out1.json"
grep -q '"legacy_available":false' "$TMPDIR/out1.json"

printf '%s\n' '{"ts":1,"mac":"aa:bb:cc:dd:ee:01","rx":10,"tx":20}' > "$TMPDIR/data/stats_raw.jsonl"
printf '%s\n' '{"schema":1,"ts":1,"date":"2026-04-27","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":10,"tx":20}' > "$TMPDIR/data/stats_shadow_raw.jsonl"

HNC="$TMPDIR" HNC_TEST_MODE=1 sh "$ROOT/bin/stats_source_diag.sh" text > "$TMPDIR/out2.txt"
grep -q 'legacy_available=true' "$TMPDIR/out2.txt"
grep -q 'shadow_available=true' "$TMPDIR/out2.txt"

echo "[OK] stats_source_diag"
