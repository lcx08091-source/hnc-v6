#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP="$ROOT/.tmp/test_stats_compare.$$"
rm -rf "$TMP"
mkdir -p "$TMP/data" "$TMP/run" "$TMP/bin" "$TMP/logs"
cp "$ROOT/bin/stats_compare.sh" "$TMP/bin/stats_compare.sh"
chmod 755 "$TMP/bin/stats_compare.sh"

cat > "$TMP/data/stats_daily.jsonl" <<'JSON'
{"date":"2026-04-26","mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":2000}
{"date":"2026-04-26","mac":"aa:bb:cc:dd:ee:02","rx":3000,"tx":4000}
JSON
cat > "$TMP/data/stats_shadow_daily.jsonl" <<'JSON'
{"schema":1,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:01","mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":2000,"samples":2,"baseline":"first_sample","source":"shadow_rollup","updated_ts":1}
{"schema":1,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:02","mac":"aa:bb:cc:dd:ee:02","rx":3000,"tx":4000,"samples":2,"baseline":"first_sample","source":"shadow_rollup","updated_ts":1}
JSON

HNC="$TMP" HNC_TEST_MODE=1 sh "$TMP/bin/stats_compare.sh" json > "$TMP/out.json"
grep -q '"status":"ok"' "$TMP/out.json"
grep -q '"matched_keys":2' "$TMP/out.json"
grep -q '"mismatched_keys":0' "$TMP/out.json"

cat >> "$TMP/data/stats_shadow_daily.jsonl" <<'JSON'
{"schema":1,"date":"2026-04-26","device_id":"mac:aa:bb:cc:dd:ee:03","mac":"aa:bb:cc:dd:ee:03","rx":9999,"tx":9999,"samples":1,"baseline":"first_sample","source":"shadow_rollup","updated_ts":1}
JSON
HNC="$TMP" HNC_TEST_MODE=1 sh "$TMP/bin/stats_compare.sh" text > "$TMP/out.txt"
grep -q 'status=warn' "$TMP/out.txt"
grep -q 'missing_in_legacy=1' "$TMP/out.txt"
[ -f "$TMP/run/stats_compare.json" ]
[ -f "$TMP/run/stats_compare.txt" ]

rm -rf "$TMP"
echo "test_stats_compare: OK"
