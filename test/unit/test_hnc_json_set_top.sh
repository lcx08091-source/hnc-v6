#!/system/bin/sh
# HNC hotfix19.0 regression tests for hnc_json set-top.
set -eu

ROOT="${TMPDIR:-/tmp}/hnc_json_190_$$"
mkdir -p "$ROOT/run" "$ROOT/data" "$ROOT/logs"
export HNC="$ROOT"
trap 'rm -rf "$ROOT"' EXIT
BIN="${HNC_JSON_BIN:-./bin/hnc_json}"
fail(){ echo "FAIL: $*" >&2; exit 1; }

cat > "$ROOT/rules.json" <<'JSON'
{
  "hotspot_ssid": "old,name",
  "auth_required": true,
  "nested": {"a": "b,c}"}
}
JSON

sh "$BIN" validate "$ROOT/rules.json" || fail validate_initial
sh "$BIN" set-top "$ROOT/rules.json" hotspot_ssid '我家,客房} "wifi" \ ok' str || fail set_ssid
sh "$BIN" validate "$ROOT/rules.json" || fail validate_after_ssid
sh "$BIN" get-top "$ROOT/rules.json" hotspot_ssid | grep -q '我家,客房}' || fail get_ssid
sh "$BIN" set-top "$ROOT/rules.json" limit_enabled false bool || fail set_bool
sh "$BIN" set-top "$ROOT/rules.json" down_mbps 8 num || fail set_num
sh "$BIN" set-top "$ROOT/rules.json" optional null null || fail set_null
sh "$BIN" validate "$ROOT/rules.json" || fail validate_final

grep -q '"limit_enabled": false' "$ROOT/rules.json" || fail bool_literal
grep -q '"down_mbps": 8' "$ROOT/rules.json" || fail num_literal
grep -q '"optional": null' "$ROOT/rules.json" || fail null_literal

echo "PASS hnc_json set-top hotfix19.0"
