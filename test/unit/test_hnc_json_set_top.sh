#!/system/bin/sh
# HNC hotfix19.0 regression tests for hnc_json set-top.
set -eu

ROOT="${TMPDIR:-/tmp}/hnc_json_190_$$"
mkdir -p "$ROOT"
trap 'rm -rf "$ROOT"' EXIT
# v5.33: 锁(run/json.lock)与备份(data/.json_backups)跟着 HNC 走; 不设就落到真实的
# /data/local/hnc(真机上 = 用户的运行目录)。hnc_json 用 sh 调, 不靠 shebang。
export HNC="$ROOT"
BIN="${HNC_JSON_BIN:-./bin/hnc_json}"
hj() { sh "$BIN" "$@"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }

cat > "$ROOT/rules.json" <<'JSON'
{
  "hotspot_ssid": "old,name",
  "auth_required": true,
  "nested": {"a": "b,c}"}
}
JSON

hj validate "$ROOT/rules.json" || fail validate_initial
hj set-top "$ROOT/rules.json" hotspot_ssid '我家,客房} "wifi" \ ok' str || fail set_ssid
hj validate "$ROOT/rules.json" || fail validate_after_ssid
hj get-top "$ROOT/rules.json" hotspot_ssid | grep -q '我家,客房}' || fail get_ssid
hj set-top "$ROOT/rules.json" limit_enabled false bool || fail set_bool
hj set-top "$ROOT/rules.json" down_mbps 8 num || fail set_num
hj set-top "$ROOT/rules.json" optional null null || fail set_null
hj validate "$ROOT/rules.json" || fail validate_final

grep -q '"limit_enabled": false' "$ROOT/rules.json" || fail bool_literal
grep -q '"down_mbps": 8' "$ROOT/rules.json" || fail num_literal
grep -q '"optional": null' "$ROOT/rules.json" || fail null_literal

echo "PASS hnc_json set-top hotfix19.0"
