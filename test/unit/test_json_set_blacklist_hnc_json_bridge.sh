#!/system/bin/sh
# hotfix19.9 regression test: blacklist bl_add/bl_del use hnc_json array primitives safely
set -eu

BASE="${TMPDIR:-/tmp}/hnc_json_blacklist_test.$$"
ROOT="$BASE/root"
SRC_DIR="$(cd "$(dirname "${HNC_TEST_FILE:-${BASH_SOURCE:-$0}}")/../.." && pwd)"
mkdir -p "$ROOT/bin" "$ROOT/data" "$ROOT/run"
cp "$SRC_DIR/bin/json_set.sh" "$ROOT/bin/json_set.sh"
cp "$SRC_DIR/bin/hnc_json" "$ROOT/bin/hnc_json"
cp "$SRC_DIR/bin/json_guard.sh" "$ROOT/bin/json_guard.sh" 2>/dev/null || true
chmod 755 "$ROOT/bin"/*.sh "$ROOT/bin/hnc_json" 2>/dev/null || true

cat > "$ROOT/data/rules.json" <<'JSON'
{"version":1,"whitelist_mode":false,"devices":{"aa:aa:aa:aa:aa:aa":{"limit_enabled":true}},"blacklist":[],"whitelist":["11:22:33:44:55:66"]}
JSON

HNC="$ROOT" sh "$ROOT/bin/json_set.sh" bl_add 'aa:bb:cc:dd:ee:ff'
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" bl_add 'aa:bb:cc:dd:ee:ff'
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" bl_add 'de:ad:be:ef:00:01'
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" bl_del 'aa:bb:cc:dd:ee:ff'
HNC="$ROOT" sh "$ROOT/bin/json_set.sh" bl_del '00:00:00:00:00:00'

if command -v grep >/dev/null 2>&1; then
  grep -q '"blacklist":\["de:ad:be:ef:00:01"\]' "$ROOT/data/rules.json" || { echo "blacklist content mismatch" >&2; cat "$ROOT/data/rules.json" >&2; exit 1; }
  grep -q '"whitelist":\["11:22:33:44:55:66"\]' "$ROOT/data/rules.json" || { echo "whitelist changed unexpectedly" >&2; cat "$ROOT/data/rules.json" >&2; exit 1; }
  grep -q '"devices":{"aa:aa:aa:aa:aa:aa"' "$ROOT/data/rules.json" || { echo "devices changed unexpectedly" >&2; cat "$ROOT/data/rules.json" >&2; exit 1; }
fi

if [ -x "$ROOT/bin/json_guard.sh" ]; then
  sh "$ROOT/bin/json_guard.sh" "$ROOT/data/rules.json" >/dev/null
fi

rm -rf "$BASE"
echo "[OK] blacklist hnc_json bridge regression passed"
