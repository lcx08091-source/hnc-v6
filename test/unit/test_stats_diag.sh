#!/system/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
TMP_BASE="$ROOT_DIR/.tmp/test_stats_diag.$$"
rm -rf "$TMP_BASE"
mkdir -p "$TMP_BASE/data" "$TMP_BASE/run" "$TMP_BASE/logs"

cat > "$TMP_BASE/data/stats_raw.jsonl" <<'JSON'
{"ts":1714000000,"mac":"aa:bb:cc:dd:ee:01","rx":100,"tx":50}
{"ts":1714000300,"mac":"aa:bb:cc:dd:ee:01","rx":200,"tx":80}
{"ts":1714000600,"mac":"aa:bb:cc:dd:ee:02","rx":10,"tx":20}
not json
JSON

cat > "$TMP_BASE/data/stats_daily.jsonl" <<'JSON'
{"date":"2026-04-26","mac":"aa:bb:cc:dd:ee:01","rx":1000,"tx":2000,"name":"phone"}
JSON

echo "2026-04-26" > "$TMP_BASE/run/stats_last_date"
echo "[stats] ok" > "$TMP_BASE/logs/stats.log"

OUT="$(HNC="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_diag.sh" json)"
echo "$OUT" | grep -q '"ok":true'
echo "$OUT" | grep -q '"raw"'
echo "$OUT" | grep -q '"daily"'
echo "$OUT" | grep -q '"invalid_lines": 1'
echo "$OUT" | grep -q '"unique_macs": 2'
echo "$OUT" | grep -q '"marker":"2026-04-26"'

TXT="$(HNC="$TMP_BASE" HNC_TEST_MODE=1 sh "$ROOT_DIR/bin/stats_diag.sh" text)"
echo "$TXT" | grep -q 'HNC stats diagnostics'
echo "$TXT" | grep -q 'raw_file='

rm -rf "$TMP_BASE"
echo "test_stats_diag.sh: OK"
